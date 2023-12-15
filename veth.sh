#!/bin/bash

    sudo ip link add veth_0 type veth peer name veth_1
    sudo ip link set dev veth_0 up
    sudo ip link set dev veth_1 up
    #ifconfig
    ip link
