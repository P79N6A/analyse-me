#
# Makefile for libnids samples.
#
# Dug Song <dugsong@monkey.org>

srcdir		= .


CC		= mips-linux-gcc
CFLAGS		= -g -O2
LDFLAGS		= 

PCAP_CFLAGS	= -I/home/jiamu/work/luochao/compat-packages-openwrt/traffic-insight-cmcc/libnids-1.24/../_install/include
PCAPLIB		= -L/home/jiamu/work/luochao/compat-packages-openwrt/traffic-insight-cmcc/libnids-1.24/../_install/lib -lpcap

LNET_CFLAGS	= -I/home/jiamu/work/luochao/compat-packages-openwrt/traffic-insight-cmcc/_install/include -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
LNETLIB		= -lnet

LIBS_CFLAGS	= -I../src $(PCAP_CFLAGS) $(LNET_CFLAGS)
LIBS		= -L../src -lnids $(PCAPLIB) $(LNETLIB) -lnsl -lm  

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: overflows printall sniff
static shared: all

overflows: overflows.o
	$(CC) -o $@ overflows.o $(LDFLAGS) $(LIBS)

printall: printall.o
	$(CC) -o $@ printall.o $(LDFLAGS) $(LIBS)

sniff: sniff.o
	$(CC) -o $@ sniff.o $(LDFLAGS) $(LIBS)

static shared install installshared:
	@true

clean:
	rm -f *.o *~ overflows printall sniff

# EOF
