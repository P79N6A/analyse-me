
include Makefile.mk

.PHONY : all prepare libhttp libb64 libev libpcap libnet libnids traffi-server

all: traffi-server
    
prepare:
	@mkdir -p $(INSTALL_ROOT)
	@mkdir -p $(INSTALL_LIB)
	@mkdir -p $(INSTALL_HEADER)
	@mkdir -p $(INSTALL_HEADER)/pcap
	@mkdir -p $(INSTALL_BIN)
	@mkdir -p $(INSTALL_CONFIG)
libhttp:prepare
	$(MAKE) -C http-parser-2.8.1 library
	cp -rfd http-parser-2.8.1/*.so* $(INSTALL_LIB)
	cp http-parser-2.8.1/http_parser.h $(INSTALL_HEADER)
libb64:prepare
	$(MAKE) -C libb64-1.2.1 all_src
	cp -rfd libb64-1.2.1/src/libb64.a $(INSTALL_LIB)
	cp -rfd libb64-1.2.1/include/b64/* 	  $(INSTALL_HEADER)
libev:prepare
	$(MAKE) -C libev-4.19
	$(MAKE) -C libev-4.19 install
libpcap:prepare
	cp -rfd libpcap/*.so* $(INSTALL_LIB)
	cp libpcap/pcap.h  $(INSTALL_HEADER)
	cp libpcap/pcap/*  $(INSTALL_HEADER)/pcap
libnet:libpcap
	$(MAKE) -C libnet-1.2-rc3
	$(MAKE) -C libnet-1.2-rc3 install
libnids:libnet libev
	$(MAKE) -C libnids-1.24 \
		LNETLIB="-L$(INSTALL_LIB) -lnet" \
		PCAPLIB="-L$(INSTALL_LIB) -lpcap" \
		all install
traffi-server:libnids  libb64 libhttp
	echo "Now start compile server"
distclean:
	-$(MAKE) -C http-parser-2.8.1  distclean 
	-$(MAKE) -C libb64-1.2.1 distclean
	-$(MAKE) -C libev-4.19 	 distclean
	-$(MAKE) -C libnet-1.2-rc3 	 distclean
clean:
	@echo "-----------------clean start---------------------"
	-rm -rf $(INSTALL_ROOT)
	-$(MAKE) -C http-parser-2.8.1  	clean 
	-$(MAKE) -C libb64-1.2.1 		clean
	-$(MAKE) -C libev-4.19 	 		clean
	-$(MAKE) -C libnet-1.2-rc3 	 	clean

	@echo "-----------------clean end---------------------"
##	
##
