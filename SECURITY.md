# Security

Ferry runs with `CAP_BPF` and `CAP_NET_ADMIN` and parses untrusted packets
in XDP, so a bug in the packet path can be a security issue even when it
only looks like a crash or a drop.

## Reporting

Please don't open a public issue. Report through GitHub's private
vulnerability reporting (**Security → Report a vulnerability** on the
repository). Include the kernel version, NIC driver, and a packet capture or
reproducer if you have one.

This is a personal project with no response-time guarantee, but reports are
read and fixed first.

## Supported versions

Only `main` is supported until there is a tagged release.
