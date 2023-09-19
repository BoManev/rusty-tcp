## Intro
Use [TUN/TAP]{https://www.kernel.org/doc/Documentation/networking/tuntap.txt} to create a "user-space" network. This allows our user-space TCP to forward and receive packets thru the kernel. Just opening a raw socket, with libpnet, will allow the kernel networking stack, including TCP, to process packets, which could interfere with our TCP implementation.

## Tips
```bash
# This gives network admin priviliges to process running the TCP stack.
sudo setcap cap_net_admin=eip target/release/rusty-tcp
```
```bash
# This gives network admin priviliges to process running the TCP stack.
sudo setcap cap_net_admin=eip target/release/rusty-tcp
```

## Resources
- [TRANSMISSION CONTROL PROTOCOL (RFC793)]{https://www.ietf.org/rfc/rfc793.txt}
- [A TCP/IP Tutorial (RFC1180)]{https://www.rfc-editor.org/rfc/rfc1180}
- [Ether Type]{https://en.wikipedia.org/wiki/EtherType}
    - 0x0800 	Internet Protocol version 4 (IPv4) 
    - 0x86DD 	Internet Protocol Version 6 (IPv6) 
