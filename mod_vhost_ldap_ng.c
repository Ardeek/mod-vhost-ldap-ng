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

#include <unistd.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_version.h"
#include "apr_ldap.h"
#include "apr_reslist.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "util_ldap.h"
#include "util_script.h"
#include "sys/types.h"
#include "pwd.h"
#include "grp.h"

#if !defined(APU_HAS_LDAP) && !defined(APR_HAS_LDAP)
#error mod_vhost_ldap_ng requires APR-util to have LDAP support built in
#endif

#if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
#define HAVE_UNIX_SUEXEC
#endif

#ifdef HAVE_UNIX_SUEXEC
#include "unixd.h"              /* Contains the suexec_identity hook used on Unix */
#endif

#define MIN_UID 100
#define MIN_GID 100

#define MAX_FAILURES 5

module AP_MODULE_DECLARE_DATA vhost_ldap_ng_module;

static LDAP *ldapconn;
static apr_pool_t *vhost_ldap_pool = NULL;
static apr_hash_t *requestscache = NULL;

typedef enum {
	MVL_UNSET, MVL_DISABLED, MVL_ENABLED
} mod_vhost_ldap_status_e;

typedef struct mod_vhost_ldap_config_t {
	mod_vhost_ldap_status_e enabled;			/* Is vhost_ldap enabled? */

	/* These parameters are all derived from the VhostLDAPURL directive */
	char *url;				/* String representation of LDAP URL */

	char *host;				/* Name of the LDAP server (or space separated list) */
	int port;				/* Port of the LDAP server */
	char *basedn;			/* Base DN to do all searches from */
	int scope;				/* Scope of the search */
	char *filter;			/* Filter to further limit the search  */
	deref_options deref;		/* how to handle alias dereferening */

	char *binddn;			/* DN to bind to server (can be NULL) */
	char *bindpw;			/* Password to bind to server (can be NULL) */

	int have_deref;                     /* Set if we have found an Deref option */
	int have_ldap_url;			/* Set if we have found an LDAP url */

	int secure;				/* True if SSL connections are requested */

	char *fallback;                     /* Fallback virtual host */
	char *rootdir;
	
} mod_vhost_ldap_config_t;

typedef struct mod_vhost_ldap_request_t {
	char *dn;				/* The saved dn from a successful search */
	char *name;				/* ServerName */
	char *admin;			/* ServerAdmin */
	char *docroot;			/* DocumentRoot */
	char *cgiroot;			/* ScriptAlias */
	char *uid;				/* Suexec Uid */
	char *gid;				/* Suexec Gid */
	apr_time_t expires;		/* Expire time from cache */
	apr_array_header_t *aliases;
	apr_array_header_t *redirects;	
} mod_vhost_ldap_request_t;

typedef struct alias_t {
	char *src;
	char *dst;
	char *redir_status;
	int iscgi;
} alias_t;

char *attributes[] =
	{ "apacheServerName", "apacheDocumentRoot", "apacheScriptAlias", "apacheSuexecUid", "apacheSuexecGid", "apacheServerAdmin", "apacheAlias", "apacheRedirect", 0 };

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

	/* make sure that mod_ldap (util_ldap) is loaded */
	if (ap_find_linked_module("util_ldap.c") == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, s,
			"Module mod_ldap missing. Mod_ldap (aka. util_ldap) "
			"must be loaded in order for mod_vhost_ldap_ng to function properly");
		return HTTP_INTERNAL_SERVER_ERROR;
    	}

	ap_add_version_component(p, MOD_VHOST_LDAP_VERSION);

	return OK;
}

static void *
mod_vhost_ldap_create_server_config (apr_pool_t *p, server_rec *s)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)apr_pcalloc(p, sizeof (mod_vhost_ldap_config_t));

	conf->enabled = MVL_UNSET;
	conf->have_ldap_url = 0;
	conf->have_deref = 0;
	conf->binddn = NULL;
	conf->bindpw = NULL;
	conf->deref = always;
	conf->fallback = NULL;
	conf->rootdir = NULL;
	return conf;
}

static void *
mod_vhost_ldap_merge_server_config(apr_pool_t *p, void *parentv, void *childv)
{
	mod_vhost_ldap_config_t *parent = (mod_vhost_ldap_config_t *) parentv;
	mod_vhost_ldap_config_t *child  = (mod_vhost_ldap_config_t *) childv;
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)apr_pcalloc(p, sizeof(mod_vhost_ldap_config_t));

	if (child->enabled == MVL_UNSET)
		conf->enabled = parent->enabled;
	else
		conf->enabled = child->enabled;

	if (child->have_ldap_url) {
		conf->have_ldap_url = child->have_ldap_url;
		conf->url = child->url;
		conf->host = child->host;
		conf->port = child->port;
		conf->basedn = child->basedn;
		conf->scope = child->scope;
		conf->filter = child->filter;
		conf->secure = child->secure;
	} else {
		conf->have_ldap_url = parent->have_ldap_url;
		conf->url = parent->url;
		conf->host = parent->host;
		conf->port = parent->port;
		conf->basedn = parent->basedn;
		conf->scope = parent->scope;
		conf->filter = parent->filter;
		conf->secure = parent->secure;
	}
	if (child->have_deref) {
		conf->have_deref = child->have_deref;
		conf->deref = child->deref;
	} else {
		conf->have_deref = parent->have_deref;
		conf->deref = parent->deref;
	}

	conf->binddn = (child->binddn ? child->binddn : parent->binddn);
	conf->bindpw = (child->bindpw ? child->bindpw : parent->bindpw);

	conf->fallback = (child->fallback ? child->fallback : parent->fallback);
	
	conf->rootdir = child->rootdir ? child->rootdir : parent->rootdir;
	
	return conf;
}

/* 
 * Use the ldap url parsing routines to break up the ldap url into
 * host and port.
 */
static const char *mod_vhost_ldap_parse_url(cmd_parms *cmd, 
						void *dummy,
						const char *url)
{
	int result;
	apr_ldap_url_desc_t *urld;
#if (APR_MAJOR_VERSION >= 1)
	apr_ldap_err_t *result_err;
#endif

	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);

	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
		cmd->server, "[mod_vhost_ldap_ng.c] url parse: `%s'", url);
    
#if (APR_MAJOR_VERSION >= 1)    /* for apache >= 2.2 */
	result = apr_ldap_url_parse(cmd->pool, url, &(urld), &(result_err));
	if (result != LDAP_SUCCESS) {
		return result_err->reason;
	}
#else
	result = apr_ldap_url_parse(url, &(urld));
	if (result != LDAP_SUCCESS) {
		switch (result) {
			case LDAP_URL_ERR_NOTLDAP:
				return "LDAP URL does not begin with ldap://";
			case LDAP_URL_ERR_NODN:
				return "LDAP URL does not have a DN";
			case LDAP_URL_ERR_BADSCOPE:
				return "LDAP URL has an invalid scope";
			case LDAP_URL_ERR_MEM:
				return "Out of memory parsing LDAP URL";
			default:
				return "Could not parse LDAP URL";
		}
	}
#endif
	conf->url = apr_pstrdup(cmd->pool, url);

	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
		cmd->server, "[mod_vhost_ldap_ng.c] url parse: Host: %s", urld->lud_host);
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
		cmd->server, "[mod_vhost_ldap_ng.c] url parse: Port: %d", urld->lud_port);
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
		cmd->server, "[mod_vhost_ldap_ng.c] url parse: DN: %s", urld->lud_dn);
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
		cmd->server, "[mod_vhost_ldap_ng.c] url parse: attrib: %s", urld->lud_attrs? urld->lud_attrs[0] : "(null)");
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
		cmd->server, "[mod_vhost_ldap_ng.c] url parse: scope: %s", 
	(urld->lud_scope == LDAP_SCOPE_SUBTREE? "subtree" : 
			urld->lud_scope == LDAP_SCOPE_BASE? "base" : 
			urld->lud_scope == LDAP_SCOPE_ONELEVEL? "onelevel" : "unknown"));
			ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0,
	cmd->server, "[mod_vhost_ldap_ng.c] url parse: filter: %s", urld->lud_filter);

    /* Set all the values, or at least some sane defaults */
	if (conf->host) {
		char *p = apr_palloc(cmd->pool, strlen(conf->host) + strlen(urld->lud_host) + 2);
		strcpy(p, urld->lud_host);
		strcat(p, " ");
		strcat(p, conf->host);
		conf->host = p;
	} else {
		conf->host = urld->lud_host? apr_pstrdup(cmd->pool, urld->lud_host) : "localhost";
	}
	conf->basedn = urld->lud_dn? apr_pstrdup(cmd->pool, urld->lud_dn) : "";

	conf->scope = urld->lud_scope == LDAP_SCOPE_ONELEVEL ?
		LDAP_SCOPE_ONELEVEL : LDAP_SCOPE_SUBTREE;

	if (urld->lud_filter) {
		if (urld->lud_filter[0] == '(') {
			/* 
			* Get rid of the surrounding parens; later on when generating the
			* filter, they'll be put back.
			*/
			conf->filter = apr_pstrdup(cmd->pool, urld->lud_filter+1);
			conf->filter[strlen(conf->filter)-1] = '\0';
		} else {
			conf->filter = apr_pstrdup(cmd->pool, urld->lud_filter);
		}
	} else {
		conf->filter = "objectClass=apacheConfig";
	}

	/* 
	"ldaps" indicates secure ldap connections desired
	*/
	if (strncasecmp(url, "ldaps", 5) == 0) {
		conf->secure = 1;
		conf->port = urld->lud_port? urld->lud_port : LDAPS_PORT;
		ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server,
			"LDAP: vhost_ldap using SSL connections");
	} else {
		conf->secure = 0;
		conf->port = urld->lud_port? urld->lud_port : LDAP_PORT;
		ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, cmd->server, 
			"LDAP: vhost_ldap not using SSL connections");
	}

	conf->have_ldap_url = 1;
#if (APR_MAJOR_VERSION < 1) /* free only required for older apr */
	apr_ldap_free_urldesc(urld);
#endif
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
		rootdir = strcat((char *)rootdir, "/");
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

static const char *mod_vhost_ldap_set_deref(cmd_parms *cmd, void *dummy, const char *deref)
{
	mod_vhost_ldap_config_t *conf = 
	(mod_vhost_ldap_config_t *)ap_get_module_config (cmd->server->module_config, &vhost_ldap_ng_module);

	if (strcmp(deref, "never") == 0 || strcasecmp(deref, "off") == 0) {
		conf->deref = never;
		conf->have_deref = 1;
	} else if (strcmp(deref, "searching") == 0) {
		conf->deref = searching;
		conf->have_deref = 1;
	} else if (strcmp(deref, "finding") == 0) {
		conf->deref = finding;
		conf->have_deref = 1;
	} else if (strcmp(deref, "always") == 0 || strcasecmp(deref, "on") == 0) {
		conf->deref = always;
		conf->have_deref = 1;
	} else {
		return "Unrecognized value for VhostLDAPAliasDereference directive";
	}
	return NULL;
}

static const char *mod_vhost_ldap_set_fallback(cmd_parms *cmd, void *dummy, const char *fallback)
{
	mod_vhost_ldap_config_t *conf =
	(mod_vhost_ldap_config_t *)ap_get_module_config(cmd->server->module_config, &vhost_ldap_ng_module);
	conf->fallback = apr_pstrdup(cmd->pool, fallback);
	return NULL;
}

command_rec mod_vhost_ldap_cmds[] = {
	AP_INIT_TAKE1("VhostLDAPURL", mod_vhost_ldap_parse_url, NULL, RSRC_CONF,
					"URL to define LDAP connection. This should be an RFC 2255 compliant\n"
					"URL of the form ldap://host[:port]/basedn[?attrib[?scope[?filter]]].\n"
					"<ul>\n"
					"<li>Host is the name of the LDAP server. Use a space separated list of hosts \n"
					"to specify redundant servers.\n"
					"<li>Port is optional, and specifies the port to connect to.\n"
					"<li>basedn specifies the base DN to start searches from\n"
					"</ul>\n"),

	AP_INIT_TAKE1 ("VhostLDAPBindDN", mod_vhost_ldap_set_binddn, NULL, RSRC_CONF,
					"DN to use to bind to LDAP server. If not provided, will do an anonymous bind."),

	AP_INIT_TAKE1("VhostLDAPBindPassword", mod_vhost_ldap_set_bindpw, NULL, RSRC_CONF,
					"Password to use to bind to LDAP server. If not provided, will do an anonymous bind."),

	AP_INIT_FLAG("VhostLDAPEnabled", mod_vhost_ldap_set_enabled, NULL, RSRC_CONF,
					"Set to off to disable vhost_ldap, even if it's been enabled in a higher tree"),

	AP_INIT_TAKE1("VhostLDAPDereferenceAliases", mod_vhost_ldap_set_deref, NULL, RSRC_CONF,
					"Determines how aliases are handled during a search. Can be one of the"
					"values \"never\", \"searching\", \"finding\", or \"always\". "
					"Defaults to always."),

	AP_INIT_TAKE1("VhostLDAPFallback", mod_vhost_ldap_set_fallback, NULL, RSRC_CONF,
					"Set default virtual host which will be used when requested hostname"
					"is not found in LDAP database. This option can be used to display"
					"\"virtual host not found\" type of page."),
	AP_INIT_TAKE1("VhostLDAProotdir", mod_vhost_ldap_set_rootdir, NULL, RSRC_CONF, "Configurable rootDir for vhosts\n"),
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

static apr_status_t mod_vhost_ldap_child_exit(void *data)
{
	if (ldapconn)
		ldap_unbind(ldapconn);
	return APR_SUCCESS;
}

static void mod_vhost_ldap_child_init(apr_pool_t * p, server_rec * s)
{
	if(!vhost_ldap_pool)
		apr_pool_create(&vhost_ldap_pool, p);
	if(!requestscache)
		requestscache = apr_hash_make(vhost_ldap_pool);
	apr_pool_cleanup_register(p, s, mod_vhost_ldap_child_exit, mod_vhost_ldap_child_exit);
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
	char *realfile = NULL;
	char *myfilter = NULL;
	alias_t *alias = NULL;
	int i = 0, ret = 0;
	LDAPMessage *ldapmsg = NULL, *vhostentry = NULL;
	// mod_vhost_ldap is disabled or we don't have LDAP Url
	if ((conf->enabled != MVL_ENABLED)||(!conf->have_ldap_url)||(!r->hostname)) {
		return DECLINED;
	}

	//Search in cache
	reqc = (mod_vhost_ldap_request_t *)get_from_requestscache(r);
	if (!reqc || (reqc && reqc->expires < apr_time_now())){
		if(!reqc)
			reqc = apr_palloc(vhost_ldap_pool, sizeof(mod_vhost_ldap_request_t));
		memset(reqc, 0, sizeof(mod_vhost_ldap_request_t));
		reqc->aliases = (apr_array_header_t *)apr_array_make(vhost_ldap_pool, 5, sizeof(alias_t));
		reqc->redirects = (apr_array_header_t *)apr_array_make(vhost_ldap_pool, 5, sizeof(alias_t));
		//Search ldap
		//TODO: Create a function
		if(!ldapconn){
			int ldap_version = LDAP_VERSION3;
			ldapconn = ldap_init(conf->host, conf->port);
			ldap_set_option(ldapconn, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
			if (ldap_simple_bind_s (ldapconn, conf->binddn, conf->bindpw) != LDAP_SUCCESS){
				ldap_unbind(ldapconn);
				ldapconn = NULL;
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,"[mod_vhost_ldap_ng.c]: ldap connect error");
				return DECLINED;
			}
		}

		myfilter = apr_psprintf(r->pool,"(&(%s)(|(apacheServerName=%s)(apacheServerAlias=%s)))",
									conf->filter, r->hostname, r->hostname);
		ret = ldap_search_s (ldapconn, conf->basedn, conf->scope, myfilter, (char **)attributes, 0, &ldapmsg);
		if(ret != LDAP_SUCCESS){
			return DECLINED;
		}
		
		vhostentry = ldap_first_entry (ldapconn, ldapmsg);
		reqc->dn = ldap_get_dn(ldapconn, vhostentry);
		
		while(attributes[i]){
			int k =0;
			char **eValues = ldap_get_values(ldapconn, vhostentry, attributes[i]);
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
							alias->iscgi = 0;
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
							alias->iscgi = 1;
						}else{
							ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
											"[mod_vhost_ldap_ng.c]: Wrong apacheScriptAlias parameter: %s", eValues[k]);
						}
					}
				}else if(strcasecmp (attributes[i], "apacheRedirect") == 0){
					while(k){
						k--; 
						if(strchr(eValues[k], ' ')){
							alias = apr_array_push(reqc->redirects);
							attribute_tokenizer((char *)eValues[k], &alias->src, &alias->dst, NULL);
							alias->iscgi = 0;
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
						r->server->error_fname = apr_pstrcat(r->pool, conf->rootdir, eValues[0], NULL);
					else
						r->server->error_fname = apr_pstrdup(r->pool, eValues[0]);;
					apr_file_open(&r->server->error_log, r->server->error_fname,
							APR_APPEND | APR_WRITE | APR_CREATE | APR_LARGEFILE,
							APR_OS_DEFAULT, r->pool);
				}
			}
			i++;
		}
		if(ldapmsg)
			ldap_msgfree(ldapmsg);
		add_to_requestscache(reqc, r);	
	}
	ap_set_module_config(r->request_config, &vhost_ldap_ng_module, reqc);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
		"[mod_vhost_ldap_ng.c]: loaded from ldap: "
		"apacheServerName: %s, "
		"apacheServerAdmin: %s, "
		"apacheDocumentRoot: %s, "
		"apacheSuexecUid: %s, "
		"apacheSuexecGid: %s",
		reqc->name, reqc->admin, reqc->docroot, reqc->uid, reqc->gid);
	
	if ((reqc->name == NULL)||(reqc->docroot == NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap_ng.c] translate: "
			"translate failed; ServerName or DocumentRoot not defined");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	//From mod_alias: checking for redirects
	alias_t *cursor = (alias_t *)reqc->redirects->elts;
	if (r->uri[0] != '/' && r->uri[0] != '\0') 
		return DECLINED;
	for(i = 0; i < reqc->redirects->nelts; i++){
		alias = (alias_t *) &cursor[i];
		if(alias_matches(r->uri, alias->src)){
			apr_table_setn(r->headers_out, "Location", alias->dst);
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
			return HTTP_MOVED_PERMANENTLY;
		}
	}
	
	/* Checking for aliases */
	cursor = (alias_t *)reqc->aliases->elts;
	for(i = 0; i < reqc->aliases->nelts; i++){
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
				if(alias->iscgi){
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
	
	if ((r->server = apr_pmemdup(r->pool, r->server, sizeof(*r->server))) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap_ng.c] translate: "
			"translate failed; Unable to copy r->server structure");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	r->server->server_hostname = reqc->name;

	if (reqc->admin) {
		r->server->server_admin = reqc->admin;
	}

	if ((r->server->module_config = apr_pmemdup(r->pool, r->server->module_config,
			sizeof(void *) *
			(total_modules + DYNAMIC_MODULE_LIMIT))) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap_ng.c] translate: "
			"translate failed; Unable to copy r->server->module_config structure");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((core = apr_pmemdup(r->pool, core, sizeof(*core))) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, 
			"[mod_vhost_ldap_ng.c] translate: "
			"translate failed; Unable to copy r->core structure");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	ap_set_module_config(r->server->module_config, &core_module, core);

	/* Stolen from server/core.c */

	if (reqc->docroot == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, 
			"[mod_vhost_ldap_ng.c] set_document_root: DocumentRoot must be a directory");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* TODO: ap_configtestonly && ap_docrootcheck && */
	if (apr_filepath_merge((char**)&core->ap_document_root, NULL, reqc->docroot,
			APR_FILEPATH_TRUENAME, r->pool) != APR_SUCCESS
			|| !ap_is_directory(r->pool, reqc->docroot)) {

		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
			"[mod_vhost_ldap_ng.c] set_document_root: Warning: DocumentRoot [%s] does not exist",
			reqc->docroot);
		core->ap_document_root = reqc->docroot;
		if(r->handler && (strcmp(r->handler, "Script") == 0))
			return OK;
	}

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
	if ((conf->enabled != MVL_ENABLED)||(!conf->have_ldap_url))
		return NULL;
		
	if ((req == NULL)||(req->uid == NULL)||(req->gid == NULL)) 
		return NULL;

	if ((ugid = apr_palloc(r->pool, sizeof(ap_unix_identity_t))) == NULL)
		return NULL;

	passwdp = getpwnam(req->uid);
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
	mod_vhost_ldap_merge_server_config,
	mod_vhost_ldap_cmds,
	mod_vhost_ldap_register_hooks,
};
