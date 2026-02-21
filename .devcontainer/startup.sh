#!/usr/bin/bash

# if ! sudo -n true 2>/dev/null; then
#     echo 'sudo-privileges already dropped, skipping...'
#     exit
# fi

#####
# INTRO
# This file is the "startup-script", that we execute whenever we start our devcontainer.
# Basically, here we want to prepare our development-environment with everything we can't
# do in the Dockerfile, like setting file-permissions of volumes or similar.
#####

# Make sure all volumes mounted are mapped to dev, our user.
sudo chown -R dev:dev /home/dev

#####
# FIREWALL
# This is a simple set of firewall rules, that prevent any intrusion into your local lan.
# Effectively we allow all INPUT traffic, but block outgoing traffic to any internal service.
# This prevents potential malware to scan our internal network. The only targets allowed are
# Containers in our docker-compose network.
# If you want to allow other internal IPs, you have to add them BEFORE the drop-lines.
#####

# Setup the basic nftables
sudo nft add table inet f
sudo nft add chain inet f i '{ type filter hook input priority filter; policy accept; }'
sudo nft add chain inet f f '{ type filter hook forward priority filter; policy drop; }'
sudo nft add chain inet f o '{ type filter hook output priority filter; policy accept; }'
# Configure INPUT rules -> allow everything, but drop invalid traffic
sudo nft add rule inet f i ct state invalid drop
# Configure OUTPUT rules -> prevent any intrusion to private networks, except for our own
# Docker-Network (the subshell extracts the docker-network from our local network-interface)
sudo nft add rule inet f o ip daddr $(ip addr show $(ip route | awk '/default/ {print $5}') | awk '/inet / {print $2}') accept
sudo nft add rule inet f o ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } drop
sudo nft add rule inet f o ip6 daddr { fd00::/8, fe80::/10 } drop

#####
# WARNING
# Remove this to retain root access while working. Usually you won't need
# root permissions, so dropping it here is the safe choice.
#####
#sudo rm /etc/sudoers.d/dev
