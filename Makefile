CPPFLAGS = -g -Wall $(shell pkg-config fuse3 --cflags) -DFUSE_USE_VERSION=31
DAEMON_LDFLAGS = $(shell pkg-config fuse3 --libs) -lpthread

all: scalard scalar
.PHONY: all

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

scalard_sources = $(wildcard src/scalard/*.c)
scalar_sources = $(wildcard src/scalar/*.c)

include $(scalard_sources:.c=.d) $(scalar_sources:.c=.d)

scalard: $(scalard_sources:.c=.o)
	$(CC) $(LDFLAGS) $(DAEMON_LDFLAGS) -o $@ $+ $(LOADLIBES) $(LDLIBS)
scalar: $(scalar_sources:.c=.o)
	$(CC) $(LDFLAGS) -o $@ $+ $(LOADLIBES) $(LDLIBS)
