#! /bin/bash

# Code for forwarding packets
echo 1 | tee proc/sys/net/ipv4/ip_forward

exit

