#
# This software is licensed under the Public Domain.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gfwpress
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_LICENSE:=CC0-1.0
PKG_MAINTAINER:=Peter-tank
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)/$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)-$(PKG_RELEASE)

#PKG_INSTALL:=1
#PKG_FIXUP:=autoreconf
#PKG_USE_MIPS16:=0
#PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/gfwpress/Default
	SECTION:=net
	# Should this package be selected by default?
	DEFAULT:=y
	CATEGORY:=Network
	TITLE:=GFW.press client
	URL:=https://github.com/chinashiyu/gfw.press.c
	# Feature FOO also needs libsodium:
	DEPENDS:=+libopenssl +libpthread
	# DEPENDS:=+libmbedtls
	# DEPENDS:=openssl-util +libopenssl
	# DEPENDS:=libopenssl +libmcrypt +libpthread
	# DEPENDS:=+libopenssl +libcrypto +libpthread
endef

Package/gfwpress = $(Package/gfwpress/Default)

define Package/gfwpress/description
	GFW.press client for openwrt.
endef

#CONFIGURE_ARGS += --disable-ssp --disable-documentation --disable-assert

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
#	./scripts/feeds install openssl-util
#	make package/openssl/compile
# Nothing to do here for us.
# By default gfwpress/src/Makefile will be used.
endef

define Build/Compile
	CFLAGS="$(TARGET_CFLAGS)"	CPPFLAGS="$(TARGET_CPPFLAGS)"
	$(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS)
endef

define Package/gfwpress/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	if [ -f /etc/config/gfwpress ]; then
		kill -9 $(pidof gfwpress) >/dev/null 2>&1
	fi
	#mv /etc/config/gfwpress /etc/config/gfwpress.bak
fi
exit 0
endef

define Package/gfwpress/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/gfwpress $(1)/usr/bin/
#	$(INSTALL_DIR) $(1)/etc
#	#$(INSTALL_CONF) files/client.json $(1)/var/etc/gfwpress.json
endef

$(eval $(call BuildPackage,gfwpress))
