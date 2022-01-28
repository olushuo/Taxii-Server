
import os, json
import uuid
import datetime, pytz
from stix2 import parse
from stix2 import Identity, Indicator, Bundle, Malware, Relationship, NetworkTraffic, IPv4Address, ObservedData
from cti_taxii2_client import Taxxi2Server, ApiRoot, Collection
from setting import STIX_CFG

class logger:
    @staticmethod
    def error(self, msg):
        print('[FDCLog.error]: {}'.format(msg))

    @staticmethod
    def debug(self, msg):
        print('[FDCLog.debug]: {}'.format(msg))


def _msg(msg):
	print(msg)


def _debug(msg):
    if os.path.exists("/tmp/cti_debug"):
        print("[CTI STIX2 Debug]: {}".format(msg))


def _create_identity(identity_dict):
    identity_info = {}
    identity_info["spec_version"] = "2.1" 
    identity_info["created"] = identity_dict.get('CreatedTime', None)
    identity_info["name"] = identity_dict['Name']
    identity_info["identity_class"] = identity_dict.get('Class', 'unknown')
    identity_info["sectors"] = identity_dict.get('Sectors', ['technology'])
    identity_info["contact_information"] = identity_dict.get('ContactInfo', '')
    identity = Identity(**identity_info)
    return identity


def _generate_sdo_indicator(incident, identity_id):
    pattern = """[ \
            network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{}' \
        ] AND [ \
            network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{}' \
        ] \
    """.format(incident[2], incident[4])
    indicator_info = {}
    indicator_info['name'] = "Incident-{}".format(incident[0])
    indicator_info['created_by_ref'] = identity_id
    indicator_info['created'] = "2021-11-30T22:09:36Z"
    indicator_info['created'] = datetime.datetime.fromtimestamp(
        incident[7], pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    indicator_info['id'] = "indicator--{}".format(uuid.uuid4())
    indicator_info['modified'] = datetime.datetime.fromtimestamp(
        incident[8], pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    indicator_info['pattern'] = pattern
    indicator_info['pattern_type'] = "stix"
    indicator_info['spec_version'] = "2.1"
    if incident[1] == 4:
        indicator_info['indicator_types'] = [ "malicious-activity" ]
    elif incident[1] == 3:
        indicator_info['indicator_types'] = [ "benign" ]
    elif incident[1] == 0:
        indicator_info['indicator_types'] = [ "unknown" ]
    else:
        indicator_info['indicator_types'] = [ "anomalous-activity" ]

    indicator = Indicator(**indicator_info)
    return indicator


def _gen_sdo_network_traffic(incident, src_ref, dst_ref):
    network_traffic_info = {}
    network_traffic_info['spec_version'] = "2.1"
    network_traffic_info['id'] = "network-traffic--{}".format(uuid.uuid4())
    # TODO: check enum_db, convert the prococol id into string, for example: 183 means smb
    # network_traffic_info['protocols'] = [ incident[6] ]
    network_traffic_info['protocols'] = [ 'smb' ]
    network_traffic_info['src_ref'] = src_ref.id
    network_traffic_info['src_port'] = incident[3]
    network_traffic_info['dst_ref'] = dst_ref.id
    network_traffic_info['dst_port'] = incident[5]
    network_traffic = NetworkTraffic(**network_traffic_info)
    return network_traffic


def _gen_sdo_opserved_data(incident, *refs):
    observed_info = {}
    observed_info['spec_version'] = "2.1"
    observed_info['id'] = "observed-data--{}".format(uuid.uuid4())
    observed_info['first_observed'] =  datetime.datetime.fromtimestamp(
        incident[7], pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    observed_info['last_observed'] = datetime.datetime.fromtimestamp(
        incident[8], pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    observed_info['number_observed'] = 1
    observed_info['object_refs'] = [] 
    for ref in refs:
        observed_info['object_refs'].append(ref.id)
    observed_data = ObservedData(**observed_info)
    return observed_data


def _generate_sco_ipv4(ip):
    ipv4_info = {}
    ipv4_info['spec_version'] = "2.1"
    ipv4_info['id'] = "ipv4-addr--{}".format(uuid.uuid4())
    ipv4_info['value'] = str(ip)
    ipv4 = IPv4Address(**ipv4_info)
    return ipv4


def _gen_sro(created, modified, type__, from__, to__):
    sro_info = {}
    sro_info['spec_version'] = "2.1"
    sro_info['id'] = "relationship--{}".format(uuid.uuid4())
    sro_info['created'] =  datetime.datetime.fromtimestamp(
        created, pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    sro_info['modified'] = datetime.datetime.fromtimestamp(
        modified, pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    sro_info['relationship_type'] = type__
    sro_info['source_ref'] = from__.id
    sro_info['target_ref'] = to__.id 
    sro = Relationship(**sro_info)
    return sro


def _create_incident_report(incident, identity_id):
    indicator = _generate_sdo_indicator(incident, identity_id)
    src_ipv4 = _generate_sco_ipv4(incident[2])
    dst_ipv4 = _generate_sco_ipv4(incident[4])
    network_traffic = _gen_sdo_network_traffic(incident, src_ipv4, dst_ipv4)
    observed_data = _gen_sdo_opserved_data(incident, network_traffic)
    based_on = _gen_sro(incident[7], incident[8], 'based-on', indicator, observed_data)

    return [indicator, src_ipv4, dst_ipv4, network_traffic, observed_data, based_on]


def _report_incident(incident, config):
    envelope = []
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root(config.get('ApiRootURL', None))
    collection = api_root.get_collection(config['CollectionID'])

    # 1. Create Identity
    identity = _create_identity(config['Identity'])
    envelope.append(identity)

    # 2. Create Indicator
    indicator = _create_incident_report(incident, identity.id)
    envelope.extend(indicator)

    # 3. Create Observed-Objects with SCOs

    # 4. Create Bundle
    envelope = Bundle(envelope)
    collection.add_bundle(envelope.serialize())
