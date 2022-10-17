#!/bin/bash

docker build -t foo .
docker rm pbuilder

docker run \
       -it \
       --rm \
       --name pbuilder \
       --mount type=bind,source="$(pwd)/..",target=/app \
       foo \
       /bin/bash -c "cd /app && ./bootstrap.sh && mkdir -p build && cd build && ../configure && make"


docker run -it --rm --name pbuilder \
       --mount type=bind,source="$(pwd)/..",target=/app \
       foo /bin/bash

# ./bootstrap.sh && mkdir build && cd $_ && ../configure && make && sudo make install

# 563B608L3169J6LSAP64JLV09G.pcapng
# caller port 25036
# callee port 25054
# pt: 0 = g711ulaw, 8=g711alaw, 9=g722
# te-pt: determined by the setup - here maybe 229 or 101

# cd /app/test
# cat 563B608L3169J6LSAP64JLV09G.pcapng | \
#   ../build/pcap_ripper \
#       --caller-port 25054 --caller-pt 8 --caller-te-pt 101 \
#       --callee-port 25036 --callee-pt 8 --callee-te-pt 229 \
#       --codec-list 0:PCMU,8:PCMA \
#       foo 3> caller.raw 4> callee.raw