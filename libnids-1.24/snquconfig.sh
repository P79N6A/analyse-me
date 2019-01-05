#!/bin/sh
echo "Now start patch libnids"
cp src/checksum.c.row src/checksum.c
patch -p1 < patches/001-no_asm_for_i386.patch
cp configure.row configure
patch -p1 < patches/002-configure.patch
echo "Now start config libnids"
./configure \
--target=mipsel-openwrt-linux --host=mipsel-openwrt-linux \
--enable-shared \
--enable-static \
--disable-libglib \
--prefix=$PWD/../_install \
--with-libnet="$PWD/../_install" 
