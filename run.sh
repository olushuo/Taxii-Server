#! /bin/bash
sudo docker image pull olushuo/cti-taxii-server:1.0
sudo docker container run --name cti-taxii-server -d -p 5000:5000 olushuo/cti-taxii-server:1.0