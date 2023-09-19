#!/bin/bash

CARGO_TARGET_DIR=./target

cargo b -r
if [[ $? -ne 0 ]]; then
    exit $?
fi

sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/rusty-tcp
$CARGO_TARGET_DIR/release/rusty-tcp &
pid=$!

sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0

trap "kill $pid" INT TERM
wait $pid
