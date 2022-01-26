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
    indicator = parse("""{
        "type": "indicator",
        "spec_version": "2.1",
        "created": "2021-01-26T23:33:39.829Z",
        "modified": "2021-01-26T23:33:39.829Z",
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
    _test_add_bundle_1(SERVER, PORT, USER, PASSWORD, '365fed99-08fa-fdcd-a1b3-fb247eb41d01')
    #_test_add_bundle_2(SERVER, PORT, USER, PASSWORD, '365fed99-08fa-fdcd-a1b3-fb247eb41d01')


