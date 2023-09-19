Use [TUN/TAP]{https://www.kernel.org/doc/Documentation/networking/tuntap.txt} to create a "user-space" network. This allows our user-space TCP to forward and receive packets thru the kernel. Just opening a raw socket, with libpnet, will allow the kernel networking stack, including TCP, to process packets, which could interfere with our TCP implementation.

```bash
# This gives network admin priviliges to process running the TCP stack.
sudo setcap cap_net_admin=eip target/release/rusty-tcp
```
