

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
				
CFLAGS 				:=-Wall -Wstrict-prototypes -Wwrite-strings -Wshadow \
						-Winit-self -Wcast-align -Wformat=2  -Wundef  -D _COMPILE_MAIN_ -D _GNU_SOURCE -DHTTP_PARSER_STRICT=1 -g
LDFLAGS 			:= -lev -lnids  -lpcap -lm  -L$(STAGING_DIR)/usr/lib -lhttp_parser -L$(STAGING_DIR)/usr/lib/libnet-1.2.x/lib -lnet -lubus -lubox -lsqlite3 -lblobmsg_json -lb64 -liconv#-lgthread-2.0 -lnsl -lglib-2.0 -lm
