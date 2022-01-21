# python 2.7

from taxii2client.v21 import Server
from stix2 import parse
from stix2 import Indicator, Bundle, Malware, Relationship

SERVER = '192.168.56.105'
PORT = 8080
USER = 'fdc'
PASSWORD = 'fortinet'

class Collection:
    _collection = None
    _index = 0
    _api_root = None

    def __init__(self, api_root, index):
        self._api_root = api_root.get_api_root_obj()
        if index < len(self._api_root.collections):
            self._index = index
            self._collection = self._api_root.collections[index]

    def print_collection(self):
        if not self._collection:
            return
        print('this is the NO.{} collection of api root (title: {})'.format(self._index, self._api_root.title))
        print('collection title: {}'.format(self._collection.title))
        print('collection id: {}'.format(self._collection.id))
        print('collection can read: {}'.format(self._collection.can_read))
        print('collection can write: {}'.format(self._collection.can_write))
        print('collection media types: {}'.format(self._collection.media_types))
        if self._collection.can_read:
            print('collection objects count: {}'.format(
                len(self._collection.get_objects().get('objects', []))))
            if len(self._collection.get_objects().get('objects', [])):
                print(self._collection.get_objects()['objects'][-1]['id'])
            print('collection manifest count: {}'.format(
                len(self._collection.get_manifest().get('objects', []))))

    def add_bundle(self, bundle):
        self._collection.add_objects(bundle)

class ApiRoot:
    _api_root = None
    _index = 0
    _default = True
    _server = None

    def __init__(self, taxii2_server, index=0, default=True):
        self._server = taxii2_server.get_server_obj()
        if default:
            self._default = default
            self._api_root = self._server.default
        else:
            if index < len(self._server.api_roots):
                self._index = index
                self._default = False
                self._api_root = self._server.api_roots[index]

    def print_api_root(self):
        if not self._api_root:
            return
        
        if self._default:
            print('this is the default api root of server (title: {})'.format(self._server.title))
        else:
            print('this is the NO.{} api root of server (title: {})'.format(self._index, self._server.title))

        print('api_root title: {}'.format(self._api_root.title))
        print('api_root description: {}'.format(self._api_root.description))
        print('api_root collections count: {}'.format(len(self._api_root.collections)))

    def get_api_root_obj(self):
        return self._api_root

    def get_sever_obj(self):
        return self._server

class Taxxi2Server:
    _server = None

    def __init__(self, server, port, user, password):
        return self._discovery(server, port, user, password)

    def _discovery(self, server, port, user, password):
        self._server = Server('http://{}:{}/taxii2/'.format(server, port), user=user, password=password)

    def print_server(self):
        if self._server:
            print('server title: {}'.format(self._server.title))
            print('server description: {}'.format(self._server.description))
            print('server contact: {}'.format(self._server.contact))
            print('server default: {}'.format(self._server.default))
            print('server api_root count: {}'.format(len(self._server.api_roots)))

    def get_server_obj(self):
        return self._server

if __name__ == "__main__":
    taxii2 = Taxxi2Server(SERVER, PORT, USER, PASSWORD)
    taxii2.print_server()

    api_root = ApiRoot(taxii2, default=False)
    api_root.print_api_root()
    api_root = ApiRoot(taxii2, 1, default=False)
    api_root.print_api_root()

    api_root = ApiRoot(taxii2, default=True)
    api_root.print_api_root()
    collection = Collection(api_root, 0)
    collection.print_collection()
    collection = Collection(api_root, 1)
    collection.print_collection()
    collection = Collection(api_root, 2)
    collection.print_collection()

    indicator = parse("""{
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--dbcbd659-c927-4f9a-994f-0a2632274394",
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

    print(indicator.serialize(pretty=True))
    malware = Malware(name='Generic malware -lushu',
                    is_family=False
    )
    relationship = Relationship(relationship_type='indicates',
                                source_ref=indicator.id,
                                target_ref=malware.id)
    bundle = Bundle(indicator, malware, relationship)
    collection.add_bundle(bundle.serialize())
    collection.print_collection()

