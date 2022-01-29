# python 2.7

import json
import pytest
from v21.setting import STIX_CFG
from v21.cti_taxii2_client import Taxxi2Server, ApiRoot, Collection
from v21.cti_stix2_generator import _report_incident

config = {}

def setup_module():
    config_file = STIX_CFG
    global config
    with open(config_file, mode='r') as f:
        config = json.load(f)

    if not config.get('Server', None) or \
        not config.get('Port', None) or \
        not config.get('User', None) or \
        not config.get('Password', None) or \
        not config.get('CollectionID', None) or \
        not config.get('Identity', None) or \
        not config.get('Identity', None).get('ID', None) or \
        not config.get('Identity', None).get('Name', None):
        print("Incorect stix configuration")
        return

    config['Identity']['ID'] = "identity--{}".format(config['Identity']['ID'])
    js = json.dumps(config, indent=4)
    print(js)

def test_server():
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    taxii2.show()

def test_api1_root():
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root('http://192.168.56.105:8080/api1/')
    api_root.show()

def test_api2_root():
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root('http://192.168.56.105:8080/api2/')
    api_root.show()

def test_default_api_root():
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root()
    api_root.show()

def test_collection_0():
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root()
    collection_id = '472c94ae-3113-4e3e-a4dd-a9f4ac7471d4'
    collection = api_root.get_collection(collection_id)
    collection.show()

def test_collection_1():
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root()
    collection_id = '52892447-4d7e-4f70-b94d-d7f22742ff63'
    collection = api_root.get_collection(collection_id)
    collection.show()

def test_collection_2():
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root()
    collection_id = '64993447-4d7e-4f70-b94d-d7f33742ee63'
    collection = api_root.get_collection(collection_id)
    collection.show()


def test_collection_3():
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root()
    collection_id = '91a7b528-80eb-42ed-a74d-c6fbd5a26116'
    collection = api_root.get_collection(collection_id)
    collection.show()

def test_collection_4():
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    taxii2.show()
    api_root = taxii2.get_api_root()
    collection_id = '365fed99-08fa-fdcd-a1b3-fb247eb41d01'
    collection = api_root.get_collection(collection_id)
    collection.show()

def test_report_incident():
    # select id, type, aipmask, aport, vipmask, vport, protocol, sts, ets from incident where ...
    incident = [2376151082326160871, 4, '10.95.7.111', 43262, '10.95.7.222', 445, 183, 1638310176, 1638310457]
    _report_incident(incident, config)

    # print out the results
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root()
    collection = api_root.get_collection(config['CollectionID'])
    collection.show()
