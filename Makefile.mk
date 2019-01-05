

TARGET_APP          :=insight-server

CORSS_COMPILE		:= mipsel-openwrt-linux-
CC 					:=$(CORSS_COMPILE)gcc
AR					:=$(CORSS_COMPILE)ar
LD					:=$(CORSS_COMPILE)ld
STRIP 				:=$(CORSS_COMPILE)strip

INSTALL_ROOT        :=$(PWD)/_install
INSTALL_LIB         :=$(INSTALL_ROOT)/lib
INSTALL_HEADER      :=$(INSTALL_ROOT)/include
INSTALL_BIN         :=$(INSTALL_ROOT)/bin
INSTALL_CONFIG      :=$(INSTALL_ROOT)/config

CFLAGS 				:=-Wall  -Winit-self -Wcast-align -Wformat=2 -D _COMPILE_MAIN_ -D _GNU_SOURCE 
#LDFLAGS 			:= -lev -lnids  -lpcap -lm  -L$(STAGING_DIR)/usr/lib -lhttp_parser -L$(STAGING_DIR)/usr/lib/libnet-1.2.x/lib -lnet -lubus -lubox -lsqlite3 -lblobmsg_json -lb64 -liconv
export CC AR LD STRIP INSTALL_LIB INSTALL_HEADER INSTALL_BIN INSTALL_CONFIG CFLAGS