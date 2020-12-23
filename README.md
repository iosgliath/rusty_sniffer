# rusty_sniffer

Wished to try Rust.
And to make a packet sniffer.

Rusty sniffer is just that :

A naive network packet listener and parser, using std and libc.

For now:
  - Datalink: 
      Ethernet 2
  - Internet : 
      Ipv4, Ipv6, ARP
  - Transport: 
      TCP, UDP, ICMP


Just prints out output for now.

Using libc to create socket and listen for packets.

Packet is then parsed by methods saved in init_knowledge() -> methods can be added there

May rewrite this in the future.
