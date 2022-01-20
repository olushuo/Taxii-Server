#! /bin/bash
sudo docker image build -t cti-taxii-server:b1.0 .
sudo docker image tag cti-taxii-server:b1.0 olushuo/cti-taxii-server:1.0
sudo docker image push olushuo/cti-taxii-server:1.0