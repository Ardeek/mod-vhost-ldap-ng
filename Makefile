APXS=apxs2
VERSION := $(shell cat VERSION)
TMPDIR := $(shell mktemp -d /tmp/mod-vhost-ldap.XXXXXXXX)

all: mod_vhost_ldap_ng.o

install:
	$(APXS) -i mod_vhost_ldap_ng.la

clean:
	rm -f *.o
	rm -f *.lo
	rm -f *.la
	rm -f *.slo
	rm -rf .libs

mod_vhost_ldap_ng.o: mod_vhost_ldap_ng.c
	$(APXS) -Wc,-O3 -Wc,-Wall -Wc,-Werror -Wc,-DMOD_VHOST_LDAP_VERSION=\\\"mod_vhost_ldap_ng/$(VERSION)\\\" -c -lldap_r mod_vhost_ldap_ng.c
withphp:
	$(APXS) -DHAVEPHP -Wc,-O3 -Wc,-Wall -Wc,-Werror -Wc,-DMOD_VHOST_LDAP_VERSION=\\\"mod_vhost_ldap_ng/$(VERSION)\\\" -c -lldap_r mod_vhost_ldap_ng.c

debug:
	$(APXS) -DHAVEPHP -Wc,-g -Wc,-Wall -Wc,-Werror -Wc,-DMOD_VHOST_LDAP_VERSION=\\\"mod_vhost_ldap_ng/$(VERSION)\\\" -c -lldap_r mod_vhost_ldap_ng.c

.PHONY: all install clean 
