EXTENSION    = pg_queryid
EXTVERSION   = $(shell grep default_version $(EXTENSION).control | sed -e "s/default_version[[:space:]]*=[[:space:]]*'\([^']*\)'/\1/")
TESTS        = $(wildcard test/sql/*.sql)
REGRESS      = $(patsubst test/sql/%.sql,%,$(TESTS))
REGRESS_OPTS = --inputdir=test

PG_CONFIG ?= pg_config

MODULE_big = pg_queryid

OBJS = pg_queryid.o

all:

release-zip: all
	git archive --format zip --prefix=pg_queryid-${EXTVERSION}/ --output ./pg_queryid-${EXTVERSION}.zip HEAD
	unzip ./pg_queryid-$(EXTVERSION).zip
	rm ./pg_queryid-$(EXTVERSION).zip
	rm ./pg_queryid-$(EXTVERSION)/.gitignore
	sed -i -e "s/__VERSION__/$(EXTVERSION)/g"  ./pg_queryid-$(EXTVERSION)/META.json
	zip -r ./pg_queryid-$(EXTVERSION).zip ./pg_queryid-$(EXTVERSION)/
	rm ./pg_queryid-$(EXTVERSION) -rf


DATA = $(wildcard *--*.sql)
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
