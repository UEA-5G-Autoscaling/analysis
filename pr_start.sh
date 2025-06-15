#!/bin/bash
# $1 - number of gNBs
# $2 - number of UEs
# $3 - time between registrations 
# $4 - time between gNB startups 
for i in $(seq 1 $1); do
    docker run -d --name packetrusher_${i} --mount type=bind,src=/root/PacketRusher/config/config_${i}.yml,dst=/PacketRusher/config/config.yml --network=host packetrusher:main multi-ue -n $2 --tr $3
    sleep $4
done