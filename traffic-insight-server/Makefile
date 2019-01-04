#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=traffic-insight-server
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk


define Package/$(PKG_NAME)
  SECTION:=snqu
  CATEGORY:=snqu
  SUBMENU:=Application
  DEPENDS:=+libnet-1.2.x +libnids-snqu +libev +libubox +libubus +libblobmsg-json +libsqlite3 +libhttpparse-snqu +libb64-snqu +libiconv-full
  TITLE:=A network intrusion detection app
endef

define Package/$(PKG_NAME)/description
	An implementation of an E-component of Network Intrusion Detection
	System.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./server/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/traffic-insight 
	$(CP) $(PKG_BUILD_DIR)/_install/insight-server $(1)/usr/bin/
	$(CP) $(PKG_BUILD_DIR)/config/* $(1)/etc/traffic-insight/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
