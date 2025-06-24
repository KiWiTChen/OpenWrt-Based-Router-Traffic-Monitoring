include $(TOPDIR)/rules.mk

PKG_NAME:=lab2
PKG_VERSION:=1.0
PKG_RELEASE:=$(shell date +%Y%m%d)

include $(INCLUDE_DIR)/package.mk

define Package/lab2
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=OpenWrt Traffic Monitor
	DEPENDS:=+libpcap
endef

define Package/lab2/description
    Advanced traffic monitoring for MediaTek Filogic routers
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -O2 \
        -o $(PKG_BUILD_DIR)/traffic_monitor \
        $(PKG_BUILD_DIR)/openwrt.c \
        $(TARGET_LDFLAGS) -lpcap
endef

define Package/lab2/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/traffic_monitor $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/traffic_monitor
endef

$(eval $(call BuildPackage,lab2))