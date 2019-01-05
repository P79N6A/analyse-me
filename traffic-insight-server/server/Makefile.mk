

TARGET_APP          :=insight-server

#CORSS_COMPILE		:=
#CC 					:=$(CORSS_COMPILE)gcc
#AR					:=$(CORSS_COMPILE)ar
#LD					:=$(CORSS_COMPILE)ld
#STRIP				:=$(CORSS_COMPILE)strip

SOURCE_DIR	:= 	$(CURDIR)/src \
				$(CURDIR)/src/daq \
				$(CURDIR)/src/rules \
				$(CURDIR)/src/snort \
				$(CURDIR)/src/record
				
CFLAGS 				:=-Wall -Winit-self  -Wformat=2  -O2 -D _COMPILE_MAIN_ -D _GNU_SOURCE -DHTTP_PARSER_STRICT=1 -D TRAFFIC_CMCC -I $(INSTALL_HEADER)
						
LDFLAGS 			:=  -L$(INSTALL_LIB)/ -lev -lnids -lm -lnet -lpcap
