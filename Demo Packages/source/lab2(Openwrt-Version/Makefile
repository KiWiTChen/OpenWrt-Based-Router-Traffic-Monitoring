include $(TOPDIR)/rules.mk


PKG_NAME:=lab2
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk


define Package/lab2
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=OpenWrt Traffic Monitor
	DEPENDS:=+libpcap
endef

define Package/lab2/description
	Traffic monitoring program for OpenWrt
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

#modified
define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/traffic_monitor \
        ./src/openwrt.c -lpcap
endef


define Package/lab2/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/traffic_monitor $(1)/usr/sbin/
endef


$(eval $(call BuildPackage,lab2))