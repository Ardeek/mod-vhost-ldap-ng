/* ============================================================
 * Copyright (c) 2003-2004, Ondrej Sury
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

/*
 * mod_vhost_ldap_ng.c --- read virtual host config from LDAP directory
 */
/*
 * mod_vhost_ldap_ng.c is a fork() of mod_vhost_ldap.c (Refer to: http://modvhostldap.alioth.debian.org/)
 */


#define CORE_PRIVATE
#ifdef APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_version.h"
#include "apr_reslist.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "util_ldap.h"
/* trick to avoid make warning */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h"

#if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
	#define HAVE_UNIX_SUEXEC
#endif

#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"              /* Contains the suexec_identity hook used on Unix */
#include "pwd.h"
#include "grp.h"
#endif

#define MIN_UID 100
#define MIN_GID 100

#define PHP_INI_USER    (1<<0)
#define PHP_INI_PERDIR  (1<<1)
#define PHP_INI_SYSTEM  (1<<2)
#define PHP_INI_STAGE_STARTUP           (1<<0)
#define PHP_INI_STAGE_SHUTDOWN          (1<<1)
#define PHP_INI_STAGE_ACTIVATE          (1<<2)
#define PHP_INI_STAGE_DEACTIVATE        (1<<3)
#define PHP_INI_STAGE_RUNTIME           (1<<4)

#define REDIR_GONE		(1<<0)
#define REDIR_PERMANENT		(1<<1)
#define REDIR_TEMP		(1<<2)
#define REDIR_SEEOTHER		(1<<3)
#define ISCGI			(1<<4)

module AP_MODULE_DECLARE_DATA vhost_ldap_ng_module;

static apr_pool_t *vhost_ldap_pool = NULL;
static apr_hash_t *requestscache = NULL;
extern int zend_alter_ini_entry (char *, uint, char *, uint, int, int);

typedef enum {
	MVL_UNSET, MVL_DISABLED, MVL_ENABLED
} mod_vhost_ldap_status_e;

typedef struct mod_vhost_ldap_config_t {
	mod_vhost_ldap_status_e enabled;	/* Is vhost_ldap enabled? */
	/* These parameters are all derived from the VhostLDAPURL directive */
	char *url;			/* String representation of LDAP URL */
	char *basedn;			/* Base DN to do all searches from */
	int scope;			/* Scope of the search */
	char *filter;			/* Filter to further limit the search  */
	char *binddn;			/* DN to bind to server (can be NULL) */
	char *bindpw;			/* Password to bind to server (can be NULL) */
	char *fallback_name;    /* Fallback virtual host ServerName*/
	char *fallback_docroot;	/* Fallback virtual host documentroot*/
	char *rootdir;
	char *php_includepath;
} mod_vhost_ldap_config_t;

typedef struct mod_vhost_ldap_request_t {
	char *dn;				/* The saved dn from a successful search */
	char *name;				/* ServerName */
	char *admin;			/* ServerAdmin */
	char *docroot;			/* DocumentRoot */
	char *cgiroot;			/* ScriptAlias */
	char *uid;				/* Suexec Uid */
	char *gid;				/* Suexec Gid */
#ifdef HAVEPHP
	char *php_includepath;
	char *php_openbasedir;
#endif	
	int decline;
	apr_time_t expires;		/* Expire time from cache */
	apr_array_header_t *aliases;
	apr_array_header_t *redirects;	
} mod_vhost_ldap_request_t;

typedef struct alias_t {
	char *src;
	char *dst;
	uint8_t flags;
} alias_t;

char *attributes[] = {
		"apacheServerName", "apacheDocumentRoot", "apacheScriptAlias", "apacheSuexecUid", "apacheSuexecGid", "apacheServerAdmin", "apacheAlias", "apacheRedirect",
#ifdef HAVEPHP
		"phpOpenBasedir", "phpIncludePath",
#endif
	0 };

static int total_modules;

//From mod_alias
static int alias_matches(const char *uri, const char *alias_fakename)
{
    const char *aliasp = alias_fakename, *urip = uri;

    while (*aliasp) {
        if (*aliasp == '/') {
            if (*urip != '/')
                return 0;

            do {
                ++aliasp;
            } while (*aliasp == '/');
            do {
                ++urip;
            } while (*urip == '/');
        }
        else {
            if (*urip++ != *aliasp++)
                return 0;
        }
    }
    if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
        return 0;
    return urip - uri;
}

static int mod_vhost_ldap_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	module **m;

	/* Stolen from modules/generators/mod_cgid.c */
	total_modules = 0;
	for (m = ap_preloaded_modules; *m != NULL; m++)
	  total_modules++;

	ap_add_version_component(p, MOD_VHOST_LDAP_VERSION);
	return OK;
}

static void *
mod_vhost_ldap_create_server_config (apr_pool_t *p, server_rec *s)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)apr_pcalloc(p, sizeof (mod_vhost_ldap_config_t));

	conf->enabled = MVL_UNSET;
	conf->binddn = NULL;
	conf->bindpw = NULL;
	conf->fallback_name = NULL;
	conf->fallback_docroot = NULL;
	conf->rootdir = NULL;
#ifdef HAVEPHP
	conf->php_includepath = ".:/usr/share/php";
#endif
	return conf;
}

static const char *mod_vhost_ldap_set_basedn(cmd_parms *cmd, 
						void *dummy,
						const char *param)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	conf->basedn = apr_pstrdup(cmd->pool, param);
	return NULL;
}

static const char *mod_vhost_ldap_set_searchscope(cmd_parms *cmd, 
						void *dummy,
						const char *param)
{
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	if(strcmp(param, "one") == 0)
		conf->scope = LDAP_SCOPE_ONELEVEL;
	else if(strcmp(param, "sub") == 0)
		conf->scope = LDAP_SCOPE_SUBTREE;
	else if(strcmp(param, "children") == 0)	
		conf->scope = LDAP_SCOPE_CHILDREN;
	else
		conf->scope = LDAP_SCOPE_SUBTREE;
	return NULL;
}

static const char *mod_vhost_ldap_set_filter(cmd_parms *cmd, 
						void *dummy,
						const char *param)
{
	mod_vhost_ldap_config_t *conf =
		ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	conf->filter = apr_pstrdup(cmd->pool, param);
	return NULL;
}

static const char *mod_vhost_ldap_parse_url(cmd_parms *cmd, 
						void *dummy,
						const char *url)
{
	
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	conf->url = apr_pstrdup(cmd->pool, url);
	
	return NULL;
}

static const char *mod_vhost_ldap_set_enabled(cmd_parms *cmd, void *dummy, int enabled)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config,	&vhost_ldap_ng_module);
	conf->enabled = (enabled) ? MVL_ENABLED : MVL_DISABLED;
	return NULL;
}

static const char *mod_vhost_ldap_set_rootdir(cmd_parms *cmd, void *dummy, const char *rootdir)
{
    int len = 0;
	mod_vhost_ldap_config_t *conf =
		(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	len = strlen(rootdir);
	if(strcmp(rootdir+len-1, "/") != 0)
		rootdir = apr_pstrcat(cmd->pool, rootdir, "/", NULL);
	conf->rootdir = apr_pstrdup(cmd->pool, rootdir);
	return NULL;
}

static const char *mod_vhost_ldap_set_binddn(cmd_parms *cmd, void *dummy, const char *binddn)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	conf->binddn = apr_pstrdup(cmd->pool, binddn);
	return NULL;
}

static const char *mod_vhost_ldap_set_bindpw(cmd_parms *cmd, void *dummy, const char *bindpw)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config,	&vhost_ldap_ng_module);
	conf->bindpw = apr_pstrdup(cmd->pool, bindpw);
	return NULL;
}

static const char *mod_vhost_ldap_set_fallback_name(cmd_parms *cmd, void *dummy, const char *fallback)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	conf->fallback_name = apr_pstrdup(cmd->pool, fallback);
	return NULL;
}

static const char *mod_vhost_ldap_set_fallback_docroot(cmd_parms *cmd, void *dummy, const char *fallback)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	conf->fallback_docroot = apr_pstrdup(cmd->pool, fallback);
	return NULL;
}

static const char *mod_vhost_ldap_set_phpincludepath(cmd_parms *cmd, void *dummy, const char *path)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	conf->php_includepath = apr_pstrdup(cmd->pool, path);
	return NULL;
}

command_rec mod_vhost_ldap_cmds[] = {
	AP_INIT_TAKE1("VhostLDAPURL", mod_vhost_ldap_parse_url, NULL, RSRC_CONF,
					"URL to define LDAP connection.\n"),
	AP_INIT_TAKE1 ("VhostLDAPBaseDN", mod_vhost_ldap_set_basedn, NULL, RSRC_CONF,	"LDAP Hostname."),
	AP_INIT_TAKE1 ("VhostLDAPSearchScope", mod_vhost_ldap_set_searchscope, NULL, RSRC_CONF,
					"LDAP Hostname."),
	AP_INIT_TAKE1 ("VhostLDAPFilter", mod_vhost_ldap_set_filter, NULL, RSRC_CONF,
					"LDAP Hostname."),
				
	AP_INIT_TAKE1 ("VhostLDAPBindDN", mod_vhost_ldap_set_binddn, NULL, RSRC_CONF,
					"DN to use to bind to LDAP server. If not provided, will do an anonymous bind."),

	AP_INIT_TAKE1("VhostLDAPBindPassword", mod_vhost_ldap_set_bindpw, NULL, RSRC_CONF,
					"Password to use to bind to LDAP server. If not provided, will do an anonymous bind."),

	AP_INIT_FLAG("VhostLDAPEnabled", mod_vhost_ldap_set_enabled, NULL, RSRC_CONF,
					"Set to off to disable vhost_ldap, even if it's been enabled in a higher tree"),

	AP_INIT_TAKE1("VhostLDAPFallbackName", mod_vhost_ldap_set_fallback_name, NULL, RSRC_CONF,
					"Set default virtual host which will be used when requested hostname"
					"is not found in LDAP database. This option can be used to display"
					"\"virtual host not found\" type of page."),
	AP_INIT_TAKE1("VhostLDAPFallbackDocumentRoot", mod_vhost_ldap_set_fallback_docroot, NULL, RSRC_CONF,
					"Set default virtual host Document Root which will be used when requested hostname"
					"is not found in LDAP database. This option can be used to display"
					"\"virtual host not found\" type of page."),
	AP_INIT_TAKE1("VhostLDAProotdir", mod_vhost_ldap_set_rootdir, NULL, RSRC_CONF, "Configurable rootDir for vhosts"),
	AP_INIT_TAKE1("phpIncludePath",mod_vhost_ldap_set_phpincludepath, NULL, RSRC_CONF, "php include_path configuration for vhost"),
	{NULL}
};

static int attribute_tokenizer(char *instr, ...)
{
	va_list arglist; 
	char *tok, **cur;
	int i = 0;
	va_start(arglist, instr);
	while((cur = va_arg(arglist, char**))){
		if(i == 0)
			*cur = apr_strtok((char *)instr, " ", &tok);
		else
			if(!(*cur = apr_strtok(NULL, " ", &tok)))
				return i;
		i++;
	};
	va_end(arglist);
	return i;
}

static int ldapconnect(LDAP **ldapconn, mod_vhost_ldap_config_t *conf)
{
	int ldapversion = LDAP_VERSION3;
	int ret;
	if(*ldapconn == NULL){
		if((ret = ldap_initialize(ldapconn, conf->url)) > 0){
			*ldapconn = NULL;
			return ret;
		}
		if((ret = ldap_set_option(*ldapconn, LDAP_OPT_PROTOCOL_VERSION, &ldapversion)) > 0){
			*ldapconn = NULL;
			return ret;
		}
		if ((ret = ldap_simple_bind_s(*ldapconn, conf->binddn, conf->bindpw)) != LDAP_SUCCESS){
			ldap_unbind(*ldapconn);
			*ldapconn = NULL;
			return ret;
		}
	}
	return 0;
}

static void ldapdestroy(LDAP **ldapconn)
{
	ldap_unbind(*ldapconn);
	*ldapconn = NULL;
}

static void mod_vhost_ldap_child_init(apr_pool_t * p, server_rec * s)
{
	if(!vhost_ldap_pool)
		apr_pool_create(&vhost_ldap_pool, p);
	if(!requestscache)
		requestscache = apr_hash_make(vhost_ldap_pool);
}

static void* get_from_requestscache(request_rec *r)
{
	mod_vhost_ldap_request_t *reqc = NULL;
	if(requestscache){
		reqc = apr_hash_get(requestscache, r->hostname, APR_HASH_KEY_STRING);
		if(reqc && reqc->expires > apr_time_now())
			return reqc;
	}
	return NULL;
}

static void add_to_requestscache(mod_vhost_ldap_request_t *reqc, request_rec *r)
{
	reqc->expires = apr_time_now() + apr_time_from_sec(1800);
	if(!requestscache)
		requestscache = apr_hash_make(vhost_ldap_pool);
	if(r->hostname)
		apr_hash_set(requestscache, r->hostname, APR_HASH_KEY_STRING, reqc);
}

#define FILTER_LENGTH MAX_STRING_LEN
static int mod_vhost_ldap_translate_name(request_rec *r)
{
	mod_vhost_ldap_request_t *reqc = NULL;
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(r->server->module_config, &vhost_ldap_ng_module);
	core_server_config *core =
		(core_server_config *)ap_get_module_config(r->server->module_config, &core_module);
	LDAP *ld = NULL;
	char *realfile = NULL;
	char *myfilter = NULL;
	alias_t *alias = NULL;
	int i = 0, ret = 0;
	LDAPMessage *ldapmsg = NULL, *vhostentry = NULL;
	// mod_vhost_ldap is disabled or we don't have LDAP Url
	if ((conf->enabled != MVL_ENABLED)||(!conf->url)||(!r->hostname)){
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
				"[mod_vhost_ldap_ng.c] Module disabled");
		return DECLINED;
	}

	//Search in cache
	reqc = (mod_vhost_ldap_request_t *)get_from_requestscache(r);
	if(!reqc){
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, 
				"[mod_vhost_ldap_ng.c] Cannot resolve data from cache");
		reqc = apr_palloc(vhost_ldap_pool, sizeof(mod_vhost_ldap_request_t));
		memset(reqc, 0, sizeof(mod_vhost_ldap_request_t));
	}
	if (reqc->expires < apr_time_now()){
		//Search ldap
		//TODO: Create a function
		while((ret = ldapconnect(&ld, conf)) != 0 && i<2){
			i++;
			ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
				"[mod_vhost_ldap_ng.c] ldapconnect: %s", ldap_err2string(ret));
		}
		if(i == 2){
			conf->enabled = MVL_DISABLED;
			return HTTP_GATEWAY_TIME_OUT;
		}

		myfilter = apr_psprintf(r->pool,"(&(%s)(|(apacheServerName=%s)(apacheServerAlias=%s)))",
									conf->filter, r->hostname, r->hostname);

		ret = ldap_search_s (ld, conf->basedn, conf->scope, myfilter, (char **)attributes, 0, &ldapmsg);
		if(ret != LDAP_SUCCESS){//SIGPIPE?
			return DECLINED;
		}
		if(ldap_count_entries(ld, ldapmsg)!=1){
			if(!conf->fallback_name || !conf->fallback_docroot){
				reqc->name = apr_pstrdup(vhost_ldap_pool, r->hostname);
				reqc->decline = DECLINED;
				add_to_requestscache(reqc, r);
				return DECLINED;
			}else{
				reqc->name = conf->fallback_name;
				reqc->docroot = conf->fallback_docroot;
			}
		}else{
			reqc->aliases = (apr_array_header_t *)apr_array_make(vhost_ldap_pool, 2, sizeof(alias_t));
			reqc->redirects = (apr_array_header_t *)apr_array_make(vhost_ldap_pool, 2, sizeof(alias_t));
			vhostentry = ldap_first_entry (ld, ldapmsg);
			reqc->dn = ldap_get_dn(ld, vhostentry);
			i=0;
			while(attributes[i]){
				int k = 0;
				char **eValues = ldap_get_values(ld, vhostentry, attributes[i]);
				if (eValues){
					k = ldap_count_values (eValues);
					if (strcasecmp(attributes[i], "apacheServerName") == 0){
						reqc->name = apr_pstrdup(vhost_ldap_pool, eValues[0]);
					}else if(strcasecmp(attributes[i], "apacheServerAdmin") == 0){
						reqc->admin = apr_pstrdup(vhost_ldap_pool, eValues[0]);
					}else if(strcasecmp(attributes[i], "apacheDocumentRoot") == 0){
						reqc->docroot = apr_pstrdup(r->pool, eValues[0]);
						/* Make it absolute, relative to ServerRoot */
						if(conf->rootdir && (strncmp(reqc->docroot, "/", 1) != 0))
							reqc->docroot = apr_pstrcat(vhost_ldap_pool, conf->rootdir, reqc->docroot, NULL);
						reqc->docroot = ap_server_root_relative(vhost_ldap_pool, reqc->docroot);
					}else if(strcasecmp (attributes[i], "apacheAlias") == 0){
						while(k){
							k--; 
							if(strchr(eValues[k], ' ')){
								alias = apr_array_push(reqc->aliases);
								attribute_tokenizer((char *)eValues[k], &alias->src, &alias->dst, NULL);
							}else{
								ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
									"[mod_vhost_ldap_ng.c]: Wrong apacheAlias parameter: %s", eValues[k]);
							}
						}
					}else if(strcasecmp (attributes[i], "apacheScriptAlias") == 0){
						while(k){
							k--; 
							if(strchr(eValues[k], ' ')){
								alias = apr_array_push(reqc->aliases);
								attribute_tokenizer((char *)eValues[k], &alias->src, &alias->dst, NULL);
								alias->flags |= ISCGI;
							}else{
								ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
									"[mod_vhost_ldap_ng.c]: Wrong apacheScriptAlias parameter: %s", eValues[k]);
							}
						}
					}else if(strcasecmp (attributes[i], "apacheRedirect") == 0){
						while(k){
							k--; 
							if(strchr(eValues[k], ' ')){
								char *rtemp[] = {NULL, NULL};
								alias = apr_array_push(reqc->redirects);
								attribute_tokenizer((char *)eValues[k], &alias->src, &rtemp[0], &rtemp[1], NULL);
								if(rtemp[1] != NULL){
									if (strcasecmp(rtemp[0], "gone") == 0)
										alias->flags |= REDIR_GONE;
									else if (strcasecmp(rtemp[0], "permanent") == 0)
										alias->flags |= REDIR_PERMANENT;
									else if (strcasecmp(rtemp[0], "temp") == 0)
										alias->flags |= REDIR_TEMP;
									else if (strcasecmp(rtemp[0], "seeother") == 0)
										alias->flags |= REDIR_SEEOTHER;
									else
										ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
											"[mod_vhost_ldap_ng.c]: Wrong apacheRedirect type: %s", rtemp[0]);
									alias->dst = rtemp[1];
								}else{
									alias->dst = rtemp[0];
								}
							}else{
								ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
									"[mod_vhost_ldap_ng.c]: Wrong apacheRedirect parameter: %s", eValues[k]);
							}
						}
					}else if(strcasecmp(attributes[i], "apacheSuexecUid") == 0){
						reqc->uid = apr_pstrdup(vhost_ldap_pool, eValues[0]);
					}else if(strcasecmp(attributes[i], "apacheSuexecGid") == 0){
						reqc->gid = apr_pstrdup(vhost_ldap_pool, eValues[0]);
					}else if(strcasecmp (attributes[i], "apacheErrorLog") == 0){
						if(conf->rootdir && (strncmp(eValues[0], "/", 1) != 0))
							r->server->error_fname = apr_pstrcat(vhost_ldap_pool, conf->rootdir, eValues[0], NULL);
						else
							r->server->error_fname = apr_pstrdup(vhost_ldap_pool, eValues[0]);;
						apr_file_open(&r->server->error_log, r->server->error_fname,
								APR_APPEND | APR_WRITE | APR_CREATE | APR_LARGEFILE,
								APR_OS_DEFAULT, r->pool);
					}
#ifdef HAVEPHP
					else if(strcasecmp (attributes[i], "phpIncludePath") == 0){
						if(conf->php_includepath)
							reqc->php_includepath = apr_pstrcat(vhost_ldap_pool, conf->php_includepath, ":", eValues[0], NULL);
						else
							reqc->php_includepath = apr_pstrdup(vhost_ldap_pool, eValues[0]);
					}else if(strcasecmp (attributes[i], "phpOpenBasedir") == 0){
						if(conf->rootdir && (strncmp(eValues[0], "/", 1) != 0))
							reqc->php_openbasedir = apr_pstrcat(vhost_ldap_pool, conf->rootdir, eValues[0], NULL);
						else
							reqc->php_openbasedir = apr_pstrdup(vhost_ldap_pool, eValues[0]);
					}
#endif
				}
				i++;
			}
		}
		if(ldapmsg)
			ldap_msgfree(ldapmsg);
		ldapdestroy(&ld);
		add_to_requestscache(reqc, r);
	}
	if(reqc->decline == DECLINED)
		return DECLINED;
	
	ap_set_module_config(r->request_config, &vhost_ldap_ng_module, reqc);
#ifdef HAVEPHP
	char *openbasedir, *include;
	if(!reqc->php_includepath)
		include = apr_pstrcat(r->pool, conf->php_includepath, ":", reqc->docroot, NULL);
	else
		include = apr_pstrcat(r->pool, reqc->php_includepath, ":", conf->php_includepath, ":", reqc->docroot, NULL);
	zend_alter_ini_entry("include_path", strlen("include_path") + 1, (void *)include, strlen(include), PHP_INI_SYSTEM, PHP_INI_STAGE_RUNTIME);
	if(reqc->php_openbasedir){
		openbasedir = apr_pstrcat(r->pool, reqc->php_openbasedir, ":", include, NULL);
		zend_alter_ini_entry("open_basedir", strlen("open_basedir") + 1, (void *)openbasedir, strlen(openbasedir), PHP_INI_SYSTEM, PHP_INI_STAGE_RUNTIME);
	}
#endif
	if ((reqc->name == NULL)||(reqc->docroot == NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap_ng.c] translate: "
			"translate failed; ServerName %s or DocumentRoot %s not defined", reqc->name, reqc->docroot);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	alias_t *cursor = NULL;
	//From mod_alias: checking for redirects
	if(reqc->redirects){
		cursor = (alias_t *)reqc->redirects->elts;
		if (r->uri[0] != '/' && r->uri[0] != '\0') 
			return DECLINED;
		for(i = 0; i < reqc->redirects->nelts; i++){
			alias = (alias_t *) &cursor[i];
			if(alias_matches(r->uri, alias->src)){
				apr_table_setn(r->headers_out, "Location", alias->dst);
				/* OLD STUFF
				if(alias->redir_status){
					if (strcasecmp(alias->redir_status, "gone") == 0)
						return  HTTP_GONE;
					else if (strcasecmp(alias->redir_status, "permanent") == 0)
						return HTTP_MOVED_PERMANENTLY;
					else if (strcasecmp(alias->redir_status, "temp") == 0)
						return HTTP_MOVED_TEMPORARILY;
					else if (strcasecmp(alias->redir_status, "seeother") == 0)
						return HTTP_SEE_OTHER;
				}
				*/
				if(alias->flags & REDIR_GONE) return HTTP_GONE;
				else if(alias->flags & REDIR_TEMP) return HTTP_MOVED_TEMPORARILY;
				else if(alias->flags & REDIR_SEEOTHER) return HTTP_SEE_OTHER;
				else return HTTP_MOVED_PERMANENTLY;
			}
		}
	}
	
	/* Checking for aliases */
	if(reqc->aliases){
		cursor = (alias_t *)reqc->aliases->elts;
		for(i = 0; reqc->aliases && i < reqc->aliases->nelts; i++){
			alias = (alias_t *) &cursor[i];
			if (alias_matches(r->uri, alias->src)) {
				/* Set exact filename for CGI script */
				realfile = apr_pstrcat(r->pool, alias->dst, r->uri + strlen(alias->src), NULL);
				/* Add apacheRootDir config param IF realfile is a realative path*/
				if(conf->rootdir && (strncmp(alias->dst, "/", 1) != 0))
					realfile = apr_pstrcat(r->pool, conf->rootdir, realfile, NULL);
				/* Let apache normalize the path */
				if((realfile = ap_server_root_relative(r->pool, realfile))) {
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
						"[mod_vhost_ldap_ng.c]: ap_document_root is: %s",
						ap_document_root(r));
					r->filename = realfile;
					if(alias->flags & ISCGI){
						//r->handler = "cgi-script";
						r->handler = "Script";
						apr_table_setn(r->notes, "alias-forced-type", r->handler);
					}
					return OK;
				}
				return OK;
			} else if (r->uri[0] == '/') {
				/* we don't set r->filename here, and let other modules do it
				* this allows other modules (mod_rewrite.c) to work as usual
				*/
				/* r->filename = apr_pstrcat (r->pool, reqc->docroot, r->uri, NULL); */
			} else {
				/* We don't handle non-file requests here */
				return DECLINED;
			}
		}
	}
	
	if ((r->server = apr_pmemdup(r->pool, r->server, sizeof(*r->server))) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap_ng.c] translate: "
			"translate failed; Unable to copy r->server structure");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	r->server->server_hostname = apr_pstrdup(r->pool,reqc->name);

	if (reqc->admin)
		r->server->server_admin = apr_pstrdup(r->pool, reqc->admin);

	core->ap_document_root = apr_pstrdup(r->pool, reqc->docroot);
	if (!ap_is_directory(r->pool, reqc->docroot))
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"[mod_vhost_ldap.c] set_document_root: Warning: DocumentRoot [%s] does not exist", core->ap_document_root);
	//ap_set_module_config(r->server->module_config, &core_module, core);

	/* Hack to allow post-processing by other modules (mod_rewrite, mod_alias) */
	return DECLINED;
}

#ifdef HAVE_UNIX_SUEXEC
static ap_unix_identity_t *mod_vhost_ldap_get_suexec_id_doer(const request_rec * r)
{
	struct passwd *passwdp;
	struct group *groupp;
	ap_unix_identity_t *ugid = NULL;
	mod_vhost_ldap_config_t *conf = 
			(mod_vhost_ldap_config_t *)ap_get_module_config(r->server->module_config,
			&vhost_ldap_ng_module);
	mod_vhost_ldap_request_t *req =
			(mod_vhost_ldap_request_t *)ap_get_module_config(r->request_config,
			&vhost_ldap_ng_module);

  // mod_vhost_ldap is disabled or we don't have LDAP Url
	if ((conf->enabled != MVL_ENABLED)||(!conf->url))
		return NULL;
		
	if ((req == NULL)||(req->uid == NULL)||(req->gid == NULL)) 
		return NULL;

	if ((ugid = apr_palloc(r->pool, sizeof(ap_unix_identity_t))) == NULL)
		return NULL;

	passwdp = getpwnam(req->uid); //Get UID and GID from aliases in LDAP
	groupp = getgrnam(req->gid);

	if ((passwdp->pw_uid < MIN_UID)||(groupp->gr_gid < MIN_GID))
		return NULL;

	ugid->uid = passwdp->pw_uid;
	ugid->gid = groupp->gr_gid;
	ugid->userdir = 0;

	return ugid;
}
#endif

static void
mod_vhost_ldap_register_hooks (apr_pool_t * p)
{
	/*
	* Run before mod_rewrite
	*/
	static const char * const aszRewrite[]={ "mod_rewrite.c", NULL };
	ap_hook_child_init(mod_vhost_ldap_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(mod_vhost_ldap_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(mod_vhost_ldap_translate_name, NULL, aszRewrite, APR_HOOK_FIRST);
	
#ifdef HAVE_UNIX_SUEXEC
	ap_hook_get_suexec_identity(mod_vhost_ldap_get_suexec_id_doer, NULL, NULL, APR_HOOK_MIDDLE);
#endif

}

module AP_MODULE_DECLARE_DATA vhost_ldap_ng_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	mod_vhost_ldap_create_server_config,
	NULL,
	mod_vhost_ldap_cmds,
	mod_vhost_ldap_register_hooks,
};
