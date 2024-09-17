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
```
![Screenshot from 2024-09-17 09-37-50](https://github.com/user-attachments/assets/44c233ee-85a4-43f2-8f65-1ef239362bab)
