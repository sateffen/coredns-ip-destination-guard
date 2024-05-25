#!/usr/bin/env bash

# Make sure we're in this directory, and not somewhere else
cd  $(dirname -- "${BASH_SOURCE[0]}")

# Clone CoreDNS (but only shallow, we don't need history)
git clone --depth=1 https://github.com/coredns/coredns.git coredns-repo

# Move the plugin config for coredns to the repo, so we build a coredns instance we want
cp plugin.cfg coredns-repo/

# Actually execute the build and move the resulting file up for us
cd coredns-repo
make coredns
mv coredns ../coredns

# clean up the repo
cd ..
rm -rf coredns-repo/
