#!/bin/sh
./configure \
--target=mipsel-openwrt-linux --host=mipsel-openwrt-linux \
--enable-shared \
--enable-static \
--with-pcap=linux --without-septel --without-dag \
--disable-can --disable-canusb --disable-dbus --disable-bluetooth \
--prefix=$PWD/../_install \
--with-libnet="$PWD/../_install" 
