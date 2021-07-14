# Packet sniffer

Captures network packets and detects possible a SYN flooding attack.
Also detects http packets to blacklisted domains and keeps a total of how many ARP packets have been received.

# On ubuntu 20.04:

## Install prerequisites

`sudo apt install build-essential libpcap-dev`

## Compilatiion

`cd src && make`

## Running

`../build/iid`


