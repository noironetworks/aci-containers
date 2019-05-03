FROM noiro/opflex-build-base
ARG BUILDOPTS="--with-static-boost --with-boost=/usr/local/boost_1_58_0"
WORKDIR /opflex
COPY libopflex /opflex/libopflex
ARG make_args=-j4
RUN cd /opflex/libopflex \
  && ./autogen.sh && ./configure --disable-assert $BUILDOPTS \
  && make $make_args && make install
COPY genie /opflex/genie
RUN cd /opflex/genie/target/libmodelgbp \
  && sh autogen.sh && ./configure --disable-static \
  && make $make_args && make install
COPY agent-ovs /opflex/agent-ovs
RUN cd /opflex/agent-ovs \
  && ./autogen.sh && ./configure $BUILDOPTS \
  && make $make_args && make install
RUN for p in `find /usr/local/lib/ /usr/local/bin/ -type f \(\
    -name 'opflex_agent' -o \
    -name 'gbp_inspect' -o \
    -name 'mcast_daemon' -o \
    -name 'mock_server' -o \
    -name 'libopflex*so*' -o \
    -name 'libmodelgbp*so*' -o \
    -name 'libopenvswitch*so*' -o \
    -name 'libsflow*so*' -o \
    -name 'libofproto*so*' \
    \)`; do \
       objcopy --only-keep-debug "$p" "$p.debug"; \
       objcopy --strip-debug "$p"; \
       objcopy --add-gnu-debuglink="$p.debug" "$p"; \
     done
