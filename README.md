# Sniffer

## Description

`Sniffer` is a very simple network package sniffer based on [libpcap](https://www.tcpdump.org). It is written in `C`.

## Usage

`Sniffer` is build with:

```shell
make
```

This results in a binary executable called `sniffer`, which is invoked with:

```shell
./sniffer "port 80"
```

The first command line argument is required and specifies a [filter](https://www.tcpdump.org/manpages/pcap-filter.7.html). Use "" for capturing all traffic.

By defaults `Sniffer` uses the first network interface it comes across. However, an interface can be explicitly selected using a second command line argument.

```shell
./sniffer "port 80" en0
```

## Notes

1. [libpcap](https://www.tcpdump.org) needs to be installed.
2. Elevated privileges are required to use `Sniffer`, as [libpcap](https://www.tcpdump.org) needs to set the network interface in promiscuous mode.

## BSD-3 License

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
