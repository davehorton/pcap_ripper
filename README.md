# pcap_ripper

This utility takes an input stream containing pcap data and produces two output streams: one with the raw audio packets from the caller, and a second with the raw audio packets of the callee.

It is not meant to be run from a command line shell.  Rather, a parent process must spawn it and set up the appropriate input and output pipes.  Specifically, the `node-pcap-ripper` cloud function performs that function.

## Usage
```
usage: ./pcap_ripper [options]

options:
---caller-port        UDP port on which caller rtp traffic is received
---caller-pt          caller codec payload type
---callee-port        UDP port on which callee rtp traffic is received
---callee-pt          callee codec payload type
---no-eth-hdr         if present, recording file does not have an ethernet header (optional: defaults to expecting an eth header to be present)

all options are required to be provided when the executable is spawned, except for the `--no-eth-hdr` option.
```

## Building

### Prerequisites

libpcap must be installed on the build system

```
$ ./bootstrap.sh
$ mkdir build && cd $_
$ ../configure
$ make && sudo make install
```