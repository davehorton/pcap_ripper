INCLUDES= -I/usr/local/include -I${srcdir}/deps/boost_1_65_1 -I${srcdir}/deps/opus-1.2.1/include/ \
-I${srcdir}/deps/libogg-1.3.2/include -I${srcdir}/deps/libpcap-1.8.1
AM_LDFLAGS= -L/usr/local/lib
bin_PROGRAMS= pcap_ripper

pcap_ripper_SOURCES= src/main.cpp src/rtp-ripper.cpp src/utils.cpp
pcap_ripper_CPPFLAGS=-D_REENTRANT -std=c++11
pcap_ripper_LDADD= ${srcdir}/deps/boost_1_65_1/stage/lib/libboost_system.a ${srcdir}/deps/boost_1_65_1/stage/lib/libboost_regex.a \
${srcdir}/deps/opus-1.2.1/.libs/libopus.a \
${srcdir}/deps/libpcap-1.8.1/libpcap.a \
${srcdir}/deps/libogg-1.3.2/src/.libs/libogg.a

BUILT_SOURCES=${srcdir}/deps/boost_1_65_1/stage/lib/libboost_system.a \
${srcdir}/deps/opus-1.2.1/.libs/libopus.a \
${srcdir}/deps/libogg-1.3.2/src/.libs/libogg.a \
${srcdir}/deps/libpcap-1.8.1/libpcap.a

${srcdir}/deps/boost_1_65_1/stage/lib/libboost_system.a ${srcdir}/deps/boost_1_65_1/stage/lib/libboost_regex.a:
	cd ${srcdir}/deps/boost_1_65_1 && ./bootstrap.sh --with-libraries=system,filesystem,regex && ./b2 stage

${srcdir}/deps/opus-1.2.1/.libs/libopus.a:
	cd ${srcdir}/deps/opus-1.2.1 && autoreconf -fvi && ./configure && make

${srcdir}/deps/libogg-1.3.2/src/.libs/libogg.a:
	cd ${srcdir}/deps/libogg-1.3.2 && autoreconf -fvi && ./configure && make

${srcdir}/deps/libpcap-1.8.1/libpcap.a:
	cd ${srcdir}/deps/libpcap-1.8.1 && ./configure && make
