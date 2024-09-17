# mShark - Mini [Wireshark](https://www.wireshark.org/) written in Go


## Installation

```shell
CGO_ENABLED=0 go install -ldflags "-s -w" -trimpath github.com/shadowy-pycoder/mshark/cmd/mshark@latest
```
This will install the `mshark` binary to your `$GOPATH/bin` directory.

If you are getting a `Permission denied` error when running `mshark`, try running 
```shell
sudo setcap cap_net_raw+ep ~/go/bin/mshark
```

## Usage

```shell
mshark -h

                ______   __                            __       
               /      \ |  \                          |  \      
 ______ ____  |  $$$$$$\| $$____    ______    ______  | $$   __ 
|      \    \ | $$___\$$| $$    \  |      \  /      \ | $$  /  \
| $$$$$$\$$$$\ \$$    \ | $$$$$$$\  \$$$$$$\|  $$$$$$\| $$_/  $$
| $$ | $$ | $$ _\$$$$$$\| $$  | $$ /      $$| $$   \$$| $$   $$ 
| $$ | $$ | $$|  \__| $$| $$  | $$|  $$$$$$$| $$      | $$$$$$\ 
| $$ | $$ | $$ \$$    $$| $$  | $$ \$$    $$| $$      | $$  \$$\
 \$$  \$$  \$$  \$$$$$$  \$$   \$$  \$$$$$$$ \$$       \$$   \$$
                                                                                                                                                                                              
Packet Capture Tool by shadowy-pycoder 

GitHub: https://github.com/shadowy-pycoder/mshark

Usage: mshark [OPTIONS]
Options:
  -h    Show this help message and exit.
  -D    Display list of interfaces and exit.
  -c int
        The maximum number of packets to capture.
  -e string
        BPF filter expression. Example: "ip proto tcp"
  -f value
        File extension(s) to write captured data. Supported formats: stdout, txt, pcap, pcapng
  -i string
        The name of the network interface. Example: eth0 (default "any")
  -p    Promiscuous mode. This setting is ignored for "any" interface. Defaults to false.
  -s int
        The maximum length of each packet snapshot. Defaults to 65535.
  -t duration
        The maximum duration of the packet capture process. Example: 5s
  -v	Display full packet info when capturing to stdout or txt.
``` 

### Example

```shell
mshark -p -f=txt -f=stdout -f=pcapng -i eth0 -e="port 53"
```
The above command will capture packets containing `port 53` (assumed to be DNS queries) from the `eth0` interface and write the captured data to `stdout`, `txt`, and file in `pcapng` format. Files are created in the current working directory.

Output:

```shell
- Interface: eth0
- Snapshot Length: 65535
- Promiscuous Mode: true
- Timeout: 0s
- Number of Packets: 0
- BPF Filter: "port 53"
- Verbose: false

- Packet: 1 Timestamp: 2024-09-17T06:24:08+0000
==================================================================
"\033[37mEthernet Frame: Src MAC: a0:38:22:4a:f4:64 -> Dst MAC: c9:9d:7a:c2:4b:da\033[0m"
IPv4 Packet: Src IP: 192.168.100.100 -> Dst IP: 192.168.100.1
UDP Segment: Src Port: 44138 -> Dst Port: 53 Len: 59
DNS Message: Standard query query 0xc705 HTTPS incoming.telemetry.mozilla.org OPT Root 
- Packet: 2 Timestamp: 2024-09-17T06:24:08+0000
==================================================================
Ethernet Frame: Src MAC: a0:38:22:4a:f4:64 -> Dst MAC: c9:9d:7a:c2:4b:da
IPv4 Packet: Src IP: 192.168.100.100 -> Dst IP: 192.168.100.1
UDP Segment: Src Port: 53596 -> Dst Port: 53 Len: 59
DNS Message: Standard query query 0xcb86 A incoming.telemetry.mozilla.org OPT Root 
- Packet: 3 Timestamp: 2024-09-17T06:24:08+0000
==================================================================
Ethernet Frame: Src MAC: c9:9d:7a:c2:4b:da -> Dst MAC: a0:38:22:4a:f4:64
IPv4 Packet: Src IP: 192.168.100.1 -> Dst IP: 192.168.100.100
UDP Segment: Src Port: 53 -> Dst Port: 44138 Len: 197
DNS Message: Standard query reply 0xc705 HTTPS incoming.telemetry.mozilla.org CNAME incoming.telemet...
- Packet: 4 Timestamp: 2024-09-17T06:24:08+0000
==================================================================
Ethernet Frame: Src MAC: a0:38:22:4a:f4:64 -> Dst MAC: c9:9d:7a:c2:4b:da
IPv4 Packet: Src IP: 192.168.100.100 -> Dst IP: 192.168.100.1
UDP Segment: Src Port: 56746 -> Dst Port: 53 Len: 74
DNS Message: Standard query query 0x124f HTTPS telemetry-incoming.r53-2.services.mozilla.com OPT Roo...
- Packet: 5 Timestamp: 2024-09-17T06:24:08+0000
==================================================================
Ethernet Frame: Src MAC: c9:9d:7a:c2:4b:da -> Dst MAC: a0:38:22:4a:f4:64
IPv4 Packet: Src IP: 192.168.100.1 -> Dst IP: 192.168.100.100
UDP Segment: Src Port: 53 -> Dst Port: 53596 Len: 284
DNS Message: Standard query reply 0xcb86 A incoming.telemetry.mozilla.org CNAME incoming.telemetry.m...
- Packet: 6 Timestamp: 2024-09-17T06:24:08+0000
==================================================================
Ethernet Frame: Src MAC: c9:9d:7a:c2:4b:da -> Dst MAC: a0:38:22:4a:f4:64
IPv4 Packet: Src IP: 192.168.100.1 -> Dst IP: 192.168.100.100
UDP Segment: Src Port: 53 -> Dst Port: 56746 Len: 156
DNS Message: Standard query reply 0x124f HTTPS telemetry-incoming.r53-2.services.mozilla.com SOA r53...
- Packet: 7 Timestamp: 2024-09-17T06:24:08+0000
==================================================================
Ethernet Frame: Src MAC: a0:38:22:4a:f4:64 -> Dst MAC: c9:9d:7a:c2:4b:da
IPv4 Packet: Src IP: 192.168.100.100 -> Dst IP: 192.168.100.1
UDP Segment: Src Port: 54414 -> Dst Port: 53 Len: 64
DNS Message: Standard query query 0x0ed1 HTTPS optimizationguide-pa.googleapis.com OPT Root 
- Packet: 8 Timestamp: 2024-09-17T06:24:08+0000
==================================================================
Ethernet Frame: Src MAC: c9:9d:7a:c2:4b:da -> Dst MAC: a0:38:22:4a:f4:64
IPv4 Packet: Src IP: 192.168.100.1 -> Dst IP: 192.168.100.100
UDP Segment: Src Port: 53 -> Dst Port: 54414 Len: 121
DNS Message: Standard query reply 0x0ed1 HTTPS optimizationguide-pa.googleapis.com SOA googleapis.co...
```