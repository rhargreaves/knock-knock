#!/bin/bash

set -ex

ns=test
veth_host=veth_host1
veth_ns=veth_ns1
host_ip=10.0.0.1
ns_ip=10.0.0.2

sudo ip netns add $ns
sudo ip link add $veth_host type veth peer name $veth_ns
sudo ip link set $veth_ns netns $ns
sudo ip addr add $host_ip/24 dev $veth_host
sudo ip link set $veth_host up
sudo ip netns exec $ns ip addr add $ns_ip/24 dev $veth_ns
sudo ip netns exec $ns ip link set lo up
sudo ip netns exec $ns ip link set $veth_ns up
sudo ip netns exec $ns ping -c1 -W1 $host_ip

sudo ip netns del $ns
sudo ip link del $veth_host
sudo ip link del $veth_ns

