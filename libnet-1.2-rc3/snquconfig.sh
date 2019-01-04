#!/bin/sh
./configure \
--enable-shared \
--enable-static \
--prefix=$PWD/../_install \
--host=mips-buildroot-linux-uclibc
