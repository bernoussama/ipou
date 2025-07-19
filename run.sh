#!/bin/bash

cargo b --release
sudo setcap cap_net_admin=eip target/release/ipou
target/release/ipou "$1" "$2" "$3" &
pid=$!
# sudo ip addr add 10.0.0.1/24 dev utun0
sudo ip route add 10.0.0.0/8 dev utun0
# sudo ip link set up dev utun0
trap "kill $pid" INT TERM
wait $pid
