# CoreDNS IP Destination Guard

This CoreDNS plugin implements Microsoft's [Zero Trust DNS](https://techcommunity.microsoft.com/t5/networking-blog/announcing-zero-trust-dns-private-preview/ba-p/4110366)
concept for Linux - at least partially.

Zero Trust DNS is a security concept that assumes no network connection is trusted by default. Every time a system makes
a DNS request, the Zero Trust DNS system checks the returned IP addresses and adds firewall exceptions for only those
specific IPs.

So this plugin:

* Creates firewall rules that block all outgoing traffic (except explicitly allowed IPs/subnets)
* Observes all DNS responses for A and AAAA requests, adding the returned IPs as exceptions to your firewall
* Cleans up the firewall after TTL (Time To Live) plus some margin of the DNS cache entry expires (existing connections
will not get cut off, only new connections get denied)
* Allows DHCP and IPv6 neighbor discovery to not break your connectivity

That way, your system can only connect to other systems, which are allowed by your DNS provider.

## Use Case

A firewall managed by DNS acts as an additional layer of security for your systems. Especially on servers or autonomous systems
(machines, IoT and similar) the destinations are limited to a set of domains you want to connect to. You can either provide a
fixed set of domains by any other CoreDNS plugin, limiting the reachable destinations quite a lot, or use a security-focused
upstream DNS like [Quad9](https://quad9.net/) and prevent your system from connecting to any known malicious system in case an
intruder tries to execute a malicious loader. This works even if such a malicious loader tries to use its own DNS (regardless
of pure DNS, DoT or DoH), because if this plugin (so CoreDNS) doesn't process that DNS response, that IP is not allowed.

## Bonus

This plugins has a second mode, where it doesn't control the firewall's output, but the firewall's forward chain. This allows
Linux-based gateways to use their firewall to limit outgoing traffic for the whole network.

> [!WARNING]
> The gateway usage implementation is not properly tested!

## Limitations

This plugin blocks connections to all unknown IPs. If you don't add IPs/subnets to the general allow-list or don't perform a
DNS lookup with that IP as result, you can't connect. This works for most stuff, but doesn't for other, like peer-to-peer
based systems! So stuff like Tor relays or Tor exit nodes, won't work. And if you try to use this on your desktop, some
applications or application features won't work either, like Discords voice chat. But on casual webservers or similar, it works
perfectly fine (I'm running it on multiple servers perfectly fine).

Applications that try to use their own DNS server (regardless of using pure DNS, DoT or DoH) won't work properly. If this plugin
(so CoreDNS) doesn't process that DNS response, the corresponding IP is not an allowed destination.

Additionally, at the moment, this plugin only supports nftables. It's build in a way to support multiple backends in the future,
but I've only implemented nftables for now, as it's the default Linux firewall interface nowadays.

## Usage

> [!NOTE]
> I tested this plugin with CoreDNS version 1.11, which is the most recent version currently.

To use this plugin, you first need a CoreDNS version, which contains this plugin. To make it easy for you, I've added
the *deployment* folder, containing a buildscript as well as instructions for building your own CoreDNS version.

In your Corefile, you have to use this plugin using this signature:

```
ipdestinationguard [MODE] [...IP-ALLOWLIST]
```

Where:

- **MODE** is either `nft-local` or `nft-gateway`. Both values tell this plugin to use nftables, but `nft-local` tells it to
use the output chain (so limit local connections), while `nft-gateway` tells it to use the forward chain (so limit forwarding
connections).
- **...IP-ALLOWLIST** is a list of IPs or CIDRs defining IPs or subnets that are allowed by default without any prior DNS
request. You usually want to add at least your upstream DNS server, which's used by the *forward* plugin.

Exampe:

```
# we add *9.9.9.9* and *149.112.112.112* as these are the IPs of quad9
# and we want to add *10.88.0.0/16* as it's the default network for podman, and the container should read each other
# but you can add as many as you want. And yes, IPv6 IPs and CIDRs work as well.
ipdestinationguard nft-local 9.9.9.9 149.112.112.112 10.88.0.0/16
```

For a complete Corefile example see *deployment/Corefile*.

## Future work

This plugin works, and I'm using it on multiple systems, so for me, it's fine, but there's still more to do, or even
more ideas to implement:

- Add more unittests. Currently, there are not a lot of them, and it would help to make sure future changes don't
break anything.
- Add metrics, like counting the currently allowed routes.
- Implement an iptables backend. Even though iptables is "legacy", it might be worth implementing, as some people
still use it.
- Maybe implement other interesting firewall integrations, like bpfilter or BSD firewall?
- Experiment with routing instead of firewalls. A friend gave me the idea to use BGP to publish allowed routes via
BGP to routers and null-route every other IP.
- Implement the rest of Microsoft's Zero Trust DNS. This includes local DNSSEC validation, DoH and mutual authentication
(client certificates) with the DNS server.
- Explore the direction of tracking DNS requests or connections by application, allowing for an even finer-grained
control of destinations.
