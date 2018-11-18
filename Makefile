#
# p0f - passive OS fingerprinting
# (c) <lcamtuf@tpi.pl>
#

CC      = gcc
CLIBS	= -lpcap
SUNLIBS	= -lsocket -lnsl -D_SUN_=1
STRIP	= strip
CFLAGS  = -O3 -Wall
FILE	= p0f
VERSION = 1.7

DISTRO  = p0f.c Makefile README COPYING tcp.h p0f.fp

all: $(FILE) strip	

$(FILE): p0f.c
	$(CC) $(CFLAGS) -DVER=\"$(VERSION)\" -o $@ $< $(CLIBS) \
	`uname|egrep -i 'sunos|solar' >/dev/null && echo "$(SUNLIBS)"`  

strip:
	strip $(FILE) || true

clean:
	rm -f core *.o $(FILE)
	rm -rf p0f-$(VERSION)

tgz: clean
	mkdir -m 755 p0f-$(VERSION)
	cp $(DISTRO) p0f-$(VERSION)/
	chmod 644 p0f-$(VERSION)/*
	tar cfvz /$(FILE).tgz p0f-$(VERSION)
	chmod 644 /$(FILE).tgz
	rm -rf p0f-$(VERSION)

publish: tgz
	scp /p0f.tgz lcamtuf@dione.ids.pl:public_html/p0f.tgz
	scp /p0f.tgz lcamtuf@dione.ids.pl:public_html/p0f-$(VERSION).tgz
	rm -f /p0f.tgz
	
