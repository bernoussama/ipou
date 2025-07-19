#!/bin/bash

cargo b --release
sudo setcap cap_net_admin=eip target/release/ipou
target/release/ipou &
pid=$!
sudo ip addr add 10.0.0.1/24 dev tun0
sudo ip route add 10.0.0.0/8 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
