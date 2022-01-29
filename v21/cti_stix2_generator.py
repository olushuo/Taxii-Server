
import os, json
import uuid
import datetime, pytz
from stix2 import parse
from stix2 import Identity, Indicator, Bundle, Malware, Relationship, NetworkTraffic, \
    IPv4Address, ObservedData, File, IntrusionSet, AttackPattern
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


def _generate_sdo_indicator(incident, dumps, identity_id):
    pattern = """[ \
network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{}' \
] AND [ \
network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{}' \
] \
""".format(incident[2], incident[4])

    for dump in dumps:
        pattern = pattern + "AND [ file:hashes.MD5 = '{}'] ".format(dump[2])
    indicator_info = {}
    indicator_info['id'] = "indicator--{}".format(uuid.uuid4())
    indicator_info['name'] = "Incident-{}".format(incident[0])
    indicator_info['created_by_ref'] = identity_id
    indicator_info['created'] = datetime.datetime.fromtimestamp(
        incident[7], pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
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


def _create_incident_report(incident, dumps, identity_id):
    indicator = _generate_sdo_indicator(incident, dumps, identity_id)
    src_ipv4 = _generate_sco_ipv4(incident[2])
    dst_ipv4 = _generate_sco_ipv4(incident[4])
    network_traffic = _gen_sdo_network_traffic(incident, src_ipv4, dst_ipv4)
    observed_data = _gen_sdo_opserved_data(incident, network_traffic)
    based_on = _gen_sro(incident[7], incident[8], 'based-on', indicator, observed_data)

    return [indicator, src_ipv4, dst_ipv4, network_traffic, observed_data, based_on]


def _get_events_by_incident(incident):
    # select id, iid, optype, dumpid from event where iid=2376151082326160871; 
    events = [
        ( 2376155568574069011, 2376151082326160871, 103, 0 ),
        ( 2376150895873548295, 2376151082326160871, 1400, 0 ),
        ( 2376150886981899098, 2376151082326160871, 1209, 0 ),
        ( 2376150880888503948, 2376151082326160871, 1204, 3832 ),
        ( 2376150879342463654, 2376151082326160871, 1200, 0 ),
        ( 2376150877044202354, 2376151082326160871, 1200, 0 ),
        ( 2376150885350945327, 2376151082326160871, 1205, 3812 ),
        ( 2376150882778026235, 2376151082326160871, 1203, 3812 ),
        ( 2376150875143749543, 2376151082326160871, 1202, 0 ),
        ( 2376150736746690961, 2376151082326160871, 102, 3818 )
    ]
    return events


def _is_file_event(event):
    if event[3]:
        return True
    return False

def _is_ips_event(event):
    if 1400 == event[2]:
        return True
    return False


def _get_dump_files(events):
    dump_id_set = set()
    for event in events:
        if event[3]:
            dump_id_set.add(event[3])

    # select id, type, md5, isvirus from dump where id in (3812, 3818, 3832);
    # if no files, return []
    return [
        (3818, 1, 'd183cc8fe6027f3895dc15029af8f3bd'),
        (3812, 0, 'd183cc8fe6027f3895dc15029af8f3bd', 1),
        (3832, 0, '51da30155efd227110c3b7c92cd676d6', 0)
    ]


def _generate_sco_file(file_info):
    sco_info = {}
    sco_info['spec_version'] = "2.1"
    sco_info['id'] = "file--{}".format(uuid.uuid4())
    if file_info[1] == 0:
        sco_info['name'] = "dumped-file-{}".format(file_info[0])
    elif file_info[1] == 1:
        sco_info['name'] = "pcap-file-{}".format(file_info[0])
    else:
        sco_info['name'] = "unknown-file-{}".format(file_info[0])
    sco_info['hashes'] = {
        "MD5": file_info[2] 
    }
    sco_file = File(**sco_info)
    return sco_file


def _generate_sdo_malware(dump):
    malware_info = {}
    malware_info['spec_version'] = "2.1"
    malware_info['id'] = "malware--{}".format(uuid.uuid4())
    malware_info['name'] = 'virus-file-{}'.format(dump[0])
    malware_info['is_family'] = False
    malware_info['description'] = 'virus file(id: {}; md5: {})'.format(dump[0], dump[2])
    malware_info['malware_types'] = [ 'virus' ]
    malware = Malware(**malware_info)
    return malware


def _create_observed_file_data_report(indicator, incident, dumps):
    bundle = []

    for dump in dumps:
        sco_file = _generate_sco_file(dump)
        bundle.append(sco_file)
        observed_data = _gen_sdo_opserved_data(incident, sco_file)
        bundle.append(observed_data)
        based_on = _gen_sro(incident[7], incident[8], 'based-on', indicator, observed_data)
        bundle.append(based_on)
        if len(dump) > 3 and dump[3]: # virus
            malware = _generate_sdo_malware(dump)
            indicates = _gen_sro(incident[7], incident[8], 'indicates', indicator, malware)
            bundle.append(malware)
            bundle.append(indicates)

    return bundle


def _gen_sdo_intrusion_set(incident):
    intrusion_info = {}
    intrusion_info['spec_version'] = "2.1"
    intrusion_info['id'] = "intrusion-set--{}".format(uuid.uuid4())
    intrusion_info['name'] = "intrusion-set-of-incident-{}".format(incident[0])
    intrusion_info['created'] = datetime.datetime.fromtimestamp(
        incident[7], pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    intrusion_info['modified'] = datetime.datetime.fromtimestamp(
        incident[8], pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    intrusion_set = IntrusionSet(**intrusion_info)
    return intrusion_set


def _create_intrusion_set(incident, indicator):
    intrusion_set = _gen_sdo_intrusion_set(incident)
    sro = _gen_sro(incident[7], incident[8], "indicates", indicator, intrusion_set)
    return [intrusion_set, sro]


def _gen_sdo_attack_pattern(incident, event):
    attack_info = {}
    attack_info['spec_version'] = "2.1"
    attack_info['id'] = "attack-pattern--{}".format(uuid.uuid4())
    attack_info['name'] = "ips-attack--event-id-{}".format(event[0])
    attack_info['created'] = datetime.datetime.fromtimestamp(
        incident[7], pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    attack_info['modified'] = datetime.datetime.fromtimestamp(
        incident[8], pytz.timezone('UTC')).strftime("%Y-%m-%dT%H:%M:%SZ")
    attack_pattern = AttackPattern(**attack_info)
    return attack_pattern


def _create_ips_attack_report(incident, event, intrusion_set, indicator):
    attack_pattern = _gen_sdo_attack_pattern(incident, event)
    sro = _gen_sro(incident[7], incident[8], "uses", intrusion_set, attack_pattern)
    return [attack_pattern, sro]


def _report_incident(incident, config):
    envelope = []
    taxii2 = Taxxi2Server(config['Server'], config['Port'], config['User'], config['Password'])
    api_root = taxii2.get_api_root(config.get('ApiRootURL', None))
    collection = api_root.get_collection(config['CollectionID'])
    
    events = _get_events_by_incident(incident)
    dumps = _get_dump_files(events)

    # 1. Create Identity
    identity = _create_identity(config['Identity'])
    envelope.append(identity)

    # 2. Create Indicator
    indicator = _create_incident_report(incident, dumps, identity.id)
    envelope.extend(indicator)

    # 3. Create Observed-Objects with SCOs
    if len(dumps):
        observed_data = _create_observed_file_data_report(indicator[0], incident, dumps)
        envelope.extend(observed_data)

    intrusion_set = []
    for event in events:
        if _is_ips_event(event):
            intrusion_set = _create_intrusion_set(incident, indicator[0])
            envelope.extend(intrusion_set)
            break
    for event in events:
        if _is_ips_event(event) and intrusion_set and intrusion_set[0]:
            observed_data = _create_ips_attack_report(incident, event, intrusion_set[0], indicator[0])
            envelope.extend(observed_data)

    # 4. Create Bundle
    envelope = Bundle(envelope)
    collection.add_bundle(envelope.serialize())
