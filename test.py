# python 2.7

import json
from taxii2client.v21 import Server
from stix2 import parse
from stix2 import Indicator, Bundle, Malware, Relationship

SERVER = '192.168.56.105'
PORT = 8080
USER = 'fdc'
PASSWORD = 'fortinet'

class Collection:
    _taxii2_collection = None
    _index = 0
    _taxii2_api_root = None

    def __init__(self, api_root, index):
        self._taxii2_api_root = api_root.get_taxii2_api_root_obj()
        if index < len(self._taxii2_api_root.collections):
            self._index = index
            self._taxii2_collection = self._taxii2_api_root.collections[index]

    def show(self):
        if not self._taxii2_collection:
            return

        print('=======================> Collection <========================='.format(self._index))
        print('Collection (id: {}) has totally {} object on site'.format(self._taxii2_collection.id,
            len(self._taxii2_collection.get_objects().get('objects', [])) \
                if self._taxii2_collection.can_read else 0 ))
        collection = {}
        collection['title'] = self._taxii2_collection.title
        collection['id'] = self._taxii2_collection.id
        collection['description'] = self._taxii2_collection.description
        collection['can_read'] = self._taxii2_collection.can_read
        collection['can_write'] = self._taxii2_collection.can_write
        collection['media_types'] = self._taxii2_collection.media_types
        collection['objects'] = self._taxii2_collection.get_objects().get('objects', []) \
            if self._taxii2_collection.can_read else []
        js = json.dumps(collection, indent=4)
        print(js)
        return

    def add_bundle(self, bundle):
        self._taxii2_collection.add_objects(bundle)

class ApiRoot:
    _url = None
    _index = 0
    _default = True
    _taxii2_server = None
    _taxii2_api_root = None

    def __init__(self, **api_root):
        server  = api_root.get('server', None)
        if not server:
            return

        self._taxii2_server = server.get_taxii2_server_obj()
        self._url = api_root.get('url', None)
        if not self._url:
            self._default = True
            self._taxii2_api_root = self._taxii2_server.default
        else:
            for i in range(len(self._taxii2_server.api_roots)):
                if self._url == self._taxii2_server.api_roots[i].url:
                    self._index = i
                    self._default = False
                    self._taxii2_api_root = self._taxii2_server.api_roots[self._index]

    def show(self):
        if not self._taxii2_api_root:
            return

        if self._default:
            print('=======================> Default API Root <=========================')
        else:
            print('=======================> NO.{} API Root <========================='.format(self._index))

        api_root = {}
        api_root['title'] = self._taxii2_api_root.title
        api_root['description'] = self._taxii2_api_root.description
        api_root['versions'] = self._taxii2_api_root.versions
        api_root['collections'] = []
        for collection in self._taxii2_api_root.collections:
            api_root['collections'].append(collection.id)
        js = json.dumps(api_root, indent=4)
        print(js)

    def get_taxii2_api_root_obj(self):
        return self._taxii2_api_root

    def get_taxii2_sever_obj(self):
        return self._taxii2_server

    def get_collection(self, id):
        for index in range(len(self._taxii2_api_root.collections)):
            if self._taxii2_api_root.collections[index].id == id:
                return Collection(self, index)
        return None


class Taxxi2Server:
    _taxii2_server = None
    _discovery = {}

    def __init__(self, server, port, user, password):
        return self._discover(server, port, user, password)

    def _discover(self, server, port, user, password):
        self._taxii2_server = Server('http://{}:{}/taxii2/'.format(server, port), user=user, password=password)

    def show(self):
        if self._taxii2_server:
            print('=======================> Server(discovery) <=========================')
            self._discovery['title'] = self._taxii2_server.title
            self._discovery['description'] = self._taxii2_server.description
            self._discovery['contact'] = self._taxii2_server.contact
            self._discovery['default'] = self._taxii2_server.default.url
            self._discovery['api_roots'] = []
            for api_root in self._taxii2_server.api_roots:
                self._discovery['api_roots'].append(api_root.url)
            js = json.dumps(self._discovery, indent=4)
            print(js)

    def get_taxii2_server_obj(self):
        return self._taxii2_server

    def get_api_root(self, url):
        api_root_info = {'server': self, 'url': url}
        return ApiRoot(**api_root_info)

def _test_server(SERVER, PORT, USER, PASSWORD):
    taxii2 = Taxxi2Server(SERVER, PORT, USER, PASSWORD)
    taxii2.show()

def _test_api_root(SERVER, PORT, USER, PASSWORD, url=None):
    taxii2 = Taxxi2Server(SERVER, PORT, USER, PASSWORD)
    api_root = taxii2.get_api_root(url)
    api_root.show()

def _test_collection(SERVER, PORT, USER, PASSWORD, collection_id, api_root_url=None):
    taxii2 = Taxxi2Server(SERVER, PORT, USER, PASSWORD)
    api_root = taxii2.get_api_root(api_root_url)
    collection = api_root.get_collection(collection_id)
    collection.show()


def _test_add_bundle_1(SERVER, PORT, USER, PASSWORD, collection_id, api_root_url=None):
    taxii2 = Taxxi2Server(SERVER, PORT, USER, PASSWORD)
    api_root = taxii2.get_api_root(api_root_url)
    collection = api_root.get_collection(collection_id)
    indicator = parse("""{
        "type": "indicator",
        "spec_version": "2.1",
        "created": "2017-09-26T23:33:39.829Z",
        "modified": "2017-09-26T23:33:39.829Z",
        "name": "File hash for malware variant",
        "indicator_types": [
            "malicious-activity"
        ],
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "pattern": "[file:hashes.md5 ='d41d8cd98f00b204e9800998ecf8427e']",
        "valid_from": "2017-09-26T23:33:39.829952Z"
    }""")

    print('[Debug]: print indicator')
    print(indicator.serialize(pretty=True))

    malware = Malware(name='Generic malware -lushu',
                    is_family=False
    )
    relationship = Relationship(relationship_type='indicates',
                                source_ref=indicator.id,
                                target_ref=malware.id)
    bundle = Bundle(indicator, malware, relationship)
    collection.add_bundle(bundle.serialize())
    collection.show()

def _test_add_bundle_2(SERVER, PORT, USER, PASSWORD, collection_id, api_root_url=None):
    taxii2 = Taxxi2Server(SERVER, PORT, USER, PASSWORD)
    api_root = taxii2.get_api_root(api_root_url)
    collection = api_root.get_collection(collection_id)
    # indicator = parse("""{
    #     "created": "2021-11-30T22:09:36Z",
    #     "id": "indicator--8b680539-bc5d-4dc8-b91d-64e8295b8740",
    #     "indicator_types": [
    #         "malicious-activity"
    #     ],
    #     "modified": "2021-11-30T22:14:17Z",
    #     "name": "Incident 2376151082326160871",
    #     "pattern": "[file:hashes.MD5 = '69630e4574ec6798239b091cda43dca0'] AND [file:hashes.MD5 = 'd183cc8fe6027f3895dc15029af8f3bd']",
    #     "pattern_type": "stix",
    #     "spec_version": "2.1",
    #     "type": "indicator",
    #     "valid_from": "2021-11-30T22:14:17Z"
    # }""")

    # print('[Debug]: print indicator')
    # print(indicator.serialize(pretty=True))
    indicator_info = {}
    indicator_info['name'] = "Incident 2376151082326160871"
    indicator_info['created'] = "2021-11-30T22:09:36Z"
    indicator_info['id'] = "indicator--8b680539-bc5d-4dc8-b91d-64e8295b8740"
    indicator_info['indicator_types'] = [ "malicious-activity" ]
    indicator_info['modified'] = "2021-11-30T22:14:17Z"
    indicator_info['pattern'] = "[file:hashes.MD5 = '69630e4574ec6798239b091cda43dca0'] AND [file:hashes.MD5 = 'd183cc8fe6027f3895dc15029af8f3bd']"
    indicator_info['pattern_type'] = "stix"
    indicator_info['spec_version'] = "2.1"
    indicator = Indicator(**indicator_info)

    # malware_pcap_1_info = {}
    # malware_pcap_1_info["name"] = "dump-3812"
    # malware_pcap_1_info["created"] = "2022-01-27T18:17:31.484328Z"
    # malware_pcap_1_info["is_family"] = False
    # malware_pcap_1_info["spec_version"] = "2.1" 
    # malware_pcap_1_info["modified"] = "2022-01-27T18:17:31.484328Z" 
    # malware_pcap_1_info["id"] = "malware--14a68929-b82b-4720-afee-6f0ed75c493f"
    # malware_pcap_1_info = Malware(**malware_pcap_1_info)

    # relationship_info = {}

    # relationship_1 = Relationship(relationship_type='indicates',
    #                             source_ref=indicator.id,
    #                             target_ref=malware_pcap_1_info.id)
    # malware1 = Malware(name='Generic malware -lushu1',
    #                 is_family=False
    # )
    obd_pcap = parse(""" {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T19:58:16.000Z",
        "modified": "2016-04-06T19:58:16.000Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 1,
        "object_refs": [
            "file--1190f2c9-166f-55f1-9706-eea3971d8082"
        ]
    } """)
    pcap_sco = {
        "type": "file", 
        "name": "pcap-3818",
        "id": "file--1190f2c9-166f-55f1-9706-eea3971d8082", 
        "spec_version": "2.1", 
        "hashes": { 
            "MD5": "d183cc8fe6027f3895dc15029af8f3bd", 
        }
    }
    relationship_2 = Relationship(relationship_type='based-on',
                                source_ref=indicator.id,
                                target_ref=obd_pcap.id)
    
    obd_dump = parse(""" {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--62c4760f-7918-41ee-9669-1afc679d5ca7",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T19:58:16.000Z",
        "modified": "2016-04-06T19:58:16.000Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 3,
        "object_refs": [
            "file--5f8d4342-1149-46e8-8813-3f857f19adc3"
        ]
    } """)
    dump_sco = {
        "type": "file", 
        "name": "dump-3812",
        "id": "file--5f8d4342-1149-46e8-8813-3f857f19adc3", 
        "spec_version": "2.1", 
        "hashes": { 
            "MD5": "69630e4574ec6798239b091cda43dca0", 
        }
    }
    relationship_1 = Relationship(relationship_type='based-on',
                                source_ref=indicator.id,
                                target_ref=obd_dump.id)
    
    # malware_pcap_1_info = {}
    # malware_pcap_1_info["name"] = "dump-3812"
    # malware_pcap_1_info["created"] = "2022-01-27T18:17:31.484328Z"
    # malware_pcap_1_info["is_family"] = False
    # malware_pcap_1_info["spec_version"] = "2.1" 
    # malware_pcap_1_info["modified"] = "2022-01-27T18:17:31.484328Z" 
    # malware_pcap_1_info["id"] = "malware--14a68929-b82b-4720-afee-6f0ed75c493f"
    # malware_pcap_1_info = Malware(**malware_pcap_1_info)

    # relationship_info = {}

    # relationship_1 = Relationship(relationship_type='indicates',
    #                             source_ref=indicator.id,
    #                             target_ref=malware_pcap_1_info.id)
    bundle = Bundle(indicator, obd_dump, relationship_1, dump_sco, obd_pcap, relationship_2, pcap_sco)
    collection.add_bundle(bundle.serialize())
    collection.show()

if __name__ == "__main__":
    _test_server(SERVER, PORT, USER, PASSWORD)
    _test_api_root(SERVER, PORT, USER, PASSWORD, url='http://192.168.56.105:8080/api1/')
    _test_api_root(SERVER, PORT, USER, PASSWORD, url='http://192.168.56.105:8080/api2/')
    _test_api_root(SERVER, PORT, USER, PASSWORD, url=None)
    _test_collection(SERVER, PORT, USER, PASSWORD, '472c94ae-3113-4e3e-a4dd-a9f4ac7471d4')
    _test_collection(SERVER, PORT, USER, PASSWORD, '52892447-4d7e-4f70-b94d-d7f22742ff63')
    _test_collection(SERVER, PORT, USER, PASSWORD, '64993447-4d7e-4f70-b94d-d7f33742ee63')
    _test_collection(SERVER, PORT, USER, PASSWORD, '91a7b528-80eb-42ed-a74d-c6fbd5a26116')
    _test_collection(SERVER, PORT, USER, PASSWORD, '365fed99-08fa-fdcd-a1b3-fb247eb41d01')

    print('|===============================================================================|')
    print('|===========================> Testing `Add bundle` <============================|')
    print('|===============================================================================|')
    # test_add_bundle_1(SERVER, PORT, USER, PASSWORD, '365fed99-08fa-fdcd-a1b3-fb247eb41d01')
    _test_add_bundle_2(SERVER, PORT, USER, PASSWORD, '365fed99-08fa-fdcd-a1b3-fb247eb41d01')


