
include Makefile.mk

.PHONY : all prepare libhttp libb64 libev libpcap libnet libnids traffi-server

all: server
    
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
	$(MAKE) -C libpcap-libpcap-1.4.0 all install
libnet:libpcap
	$(MAKE) -C libnet-1.2-rc3
	$(MAKE) -C libnet-1.2-rc3 install
libnids:libnet libev
	$(MAKE) -C libnids-1.24 \
		LNETLIB="-L$(INSTALL_LIB) -lnet" \
		PCAPLIB="-L$(INSTALL_LIB) -lpcap" \
		all install
	cp libnids-1.24/config/* $(INSTALL_CONFIG)
server:libnids
	echo "Now start compile server"
	$(MAKE) -C traffic-insight-server
	tar -cf app.tar _install
distclean:
	-$(MAKE) -C http-parser-2.8.1  distclean 
	-$(MAKE) -C libb64-1.2.1 distclean
	-$(MAKE) -C libev-4.19 	 distclean
	-$(MAKE) -C libnet-1.2-rc3 	 distclean
	-$(MAKE) -C libpcap-libpcap-1.4.0  	distclean 
clean:
	@echo "-----------------clean start---------------------"
	-rm -rf $(INSTALL_ROOT)
	-rm -rf app.tar
	-$(MAKE) -C http-parser-2.8.1  		clean 
	-$(MAKE) -C libb64-1.2.1 			clean
	-$(MAKE) -C libpcap-libpcap-1.4.0  	clean 
	-$(MAKE) -C libev-4.19 	 			clean
	-$(MAKE) -C libnet-1.2-rc3 	 		clean
	-$(MAKE) -C traffic-insight-server 	clean

	@echo "-----------------clean end---------------------"
##	
##
