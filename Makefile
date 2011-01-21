APXS=apxs2
DEBUGSIMO="true"
VERSION := $(shell cat VERSION)
DISTFILES := $(shell cat FILES)
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
	rm -rf mod_vhost_ldap-$(VERSION)
	rm -rf mod_vhost_ldap-$(VERSION).tar.gz

mod_vhost_ldap_ng.o: mod_vhost_ldap_ng.c
	$(APXS) -Wc,-Wall -Wc,-Werror -Wc,-g -Wc,-DDEBUG -Wc,-DMOD_VHOST_LDAP_VERSION=\\\"mod_vhost_ldap_ng/$(VERSION)\\\" -c -lldap_r mod_vhost_ldap_ng.c

archive:
	cd $(TMPDIR)/mod-vhost-ldap-$(VERSION) && \
	cd $(TMPDIR) && \
	tar --exclude .git/  --exclude debian/ -czf $(CURDIR)/../mod-vhost-ldap-$(VERSION).tar.gz mod-vhost-ldap-$(VERSION)

.PHONY: all install clean archive
