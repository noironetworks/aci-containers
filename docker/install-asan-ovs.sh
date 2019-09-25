#!/bin/bash

git clone https://github.com/openvswitch/ovs.git \
    && cd ovs \
    && patch -p1 < /tmp/ovs-asan.patch \
    && ./boot.sh \
    && ./configure CFLAGS="-g -O2 -fsanitize=address -fno-omit-frame-pointer -fno-common" --prefix=/usr --localstatedir=/var --sysconfdir=/etc \
    && make -j12 \
    && make install
