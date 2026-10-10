# Development Guide

Because developing a CoreDNS plugin outside of the CoreDNS repository is not exactly straightforward (or I'm just doing it wrong), here's a guide on how to work on this project. Just in case.

## Development Environment

The IP Destination Guard needs Go, make, and a Linux system using nftables. Instead of installing these dependencies directly on your system, you can use the provided devcontainer. It requires Docker and an editor that understands devcontainers, like VS Code or Zed.

The devcontainer provides all the tools you need, and because it's its own namespace, it also has its own nftables chains. Testing the IP Destination Guard inside the container therefore only reconfigures the container's firewall, not your host system.

If you need to remove the generated rules from nftables, you can use `make clean-nft`, which deletes the corresponding nftables table.

## Development

So, here's the core problem, why this guide is even necessary: To build a working CoreDNS binary using `make testbuild` you can't have a `go.mod` and `go.sum` file in the plugin directory. This is because of how `make testbuild` actually works: It downloads CoreDNS and mounts this folder as plugin into CoreDNS, as if it was an in-tree plugin. Then it builds CoreDNS. This is different from `make genericbuild` or `make archlinux` which, pass the GitHub repository to CoreDNS to handle this automatically, so it's only relevant for the testbuild, but without this, you would have to push changes to test them. On the other side,  you obviously want those files for development, so your editor can provide autocompletion and more. You can't have both at the same time, so you have to choose what you want to do right now.

To generate the `go.mod` and `go.sum` files, as well as install dependencies for local development, you can use `make init`. This will setup the project so you can get working. Using `make test` you can execute tests to see whether your changes actually work based on tests.

Once you're happy with your changes, tests are passing, you can create a testbuild by calling `make testbuild`. This will delete the `go.mod` and `go.sum` files, prepare the testbuild and execute it. The resulting `coredns`-binary is stored at *testbuild/coredns*. You can start it by executing *sudo ./testbuild/coredns -conf ./testbuild/Corefile*. Afterwards (assuming you're using the devcontainer) you can use `drill @127.0.0.1 google.de` to test DNS resolution and then check nftables with `sudo nft list table inet coredns-ip-destination-guard`.


## Using LLMs

In short: Don't let them run things. LLMs are nice for code reviews and for finding potential bugs or issues while you're developing instead of sleeping at night. But whenever LLM agents start developing, they'll want to test their changes, start the testbuild, aaaaand disconnect themselves, because the IP Destination Guard does exactly what it's supposed to do: It blocks outgoing connections.

If you really want to use an LLM, stick to static tasks: reviews, refactors, writing unit tests. Never let it execute the testbuild. Additionally, actually use the devcontainer, because an LLM with root permissions on your system, actively working on your firewall... What can go wrong?
