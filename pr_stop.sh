#!/bin/bash
docker stop $(docker ps -q --filter name=packetrusher) 
docker rm $(docker ps -aq --filter name=packetrusher)