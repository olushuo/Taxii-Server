
import os, json
import uuid, urlparse
from django import conf
import datetime, pytz
from stix2 import parse
from stix2 import Identity, Indicator, Bundle, Malware, Relationship, NetworkTraffic, \
    IPv4Address, ObservedData, File, IntrusionSet, AttackPattern, Directory, URL
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
    #if os.path.exists("/tmp/cti_debug"):
    print("[CTI STIX2 Debug]: {}".format(msg))


def _create_identity(identity_dict):
    identity_info = {}
    identity_info["spec_version"] = "2.1" 
    identity_info["created"] = identity_dict.get('created_time', None)
    identity_info["name"] = identity_dict['name']
    identity_info["identity_class"] = identity_dict.get('class', 'unknown')
    identity_info["sectors"] = identity_dict.get('sectors', ['technology'])
    identity_info["contact_information"] = identity_dict.get('contact_info', '')
    identity = Identity(**identity_info)
    return identity


def _generate_sdo_indicator(incident, dumps, wcfs, identity_id):
    pattern = """[ \
network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{}' \
] AND [ \
network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{}' \
] \
""".format(incident[2], incident[4])

    for _, dump in dumps.items():
        pattern = pattern + "AND [ file:hashes.MD5 = '{}' ] ".format(dump[0][2])
    for wcf in wcfs:
        pattern = pattern + "AND [ url:value = '{}' ] ".format(wcf)

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


def _create_incident_report(incident, dumps, wcfs, identity_id):
    indicator = _generate_sdo_indicator(incident, dumps, wcfs, identity_id)
    src_ipv4 = _generate_sco_ipv4(incident[2])
    dst_ipv4 = _generate_sco_ipv4(incident[4])
    network_traffic = _gen_sdo_network_traffic(incident, src_ipv4, dst_ipv4)
    observed_data = _gen_sdo_opserved_data(incident, network_traffic)
    based_on = _gen_sro(incident[7], incident[8], 'based-on', indicator, observed_data)

    return [indicator, src_ipv4, dst_ipv4, network_traffic, observed_data, based_on]


def _get_events_by_incident(incident):
    # select id, iid, optype, dumpid, opcmd from event where iid=2376151082326160871; 
    events = [
        ( 2376155568574069011, 2376151082326160871, 103, 0, 0 ),
        ( 2376150895873548295, 2376151082326160871, 1400, 0, 0 ),
        ( 2376150886981899098, 2376151082326160871, 1402, 0, 200 ),
        ( 2376150880888503948, 2376151082326160871, 1204, 3832, 1091),
        ( 2376150879342463654, 2376151082326160871, 1200, 0, 0 ),
        ( 2376150877044202354, 2376151082326160871, 1200, 0, 0 ),
        ( 2376150885350945327, 2376151082326160871, 1205, 3812, 1092),
        ( 2376150882778026235, 2376151082326160871, 1203, 3812, 1092),
        ( 2376150875143749543, 2376151082326160871, 1202, 0, 0 ),
        ( 2376150736746690961, 2376151082326160871, 102, 3818, 0)
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


def _get_wcf_events(events):
    wcfs = []
    for event in events:
        if 1402 != event[2]:
            continue
        # select vstring from cmds where id=event[4]
        url = 'http://www.cabelas.com'
        wcfs.append(url)
    
    wcfs.append('https://www.brasspro.com')
    return wcfs


def _get_dump_files(events):
    dumps = {}

    for event in events:
        if not dumps.has_key(event[3]):
            # select id, type, md5, isvirus from dump where id=event[3]
            file = (3818, 1, 'd183cc8fe6027f3895dc15029af8f3bd')
            # select vstring from cmds where id=event[4]
            vstring = ''
            if event[4]:
                vstring = '/home/share/lure/eicar6'
            dumps[event[3]] = (file, vstring)

    # select id, type, md5, isvirus from dump where id in (3812, 3818, 3832);
    # if no files, return []
    return {
        '3818': ((3818, 1, 'd183cc8fe6027f3895dc15029af8f3bd'), '/home/share/lure/eicar18'),
        '3812': ((3812, 0, 'd183cc8fe6027f3895dc15029af8f3bd', 1), '/home/share/lure/eicar12'),
        '3832': ((3832, 0, '51da30155efd227110c3b7c92cd676d6', 0), '')
    }



def _generate_sco_directory(path):
    sco_id = "directory--{}".format(uuid.uuid4())
    sco_info = {}
    sco_info['spec_version'] = "2.1"
    sco_info['id'] = sco_id
    sco_info['path'] = path
    return Directory(**sco_info)


def _generate_sco_url(url):
    sco_file = []
    sco_info = {}
    sco_info['spec_version'] = "2.1"
    sco_info['id'] = "url--{}".format(uuid.uuid4())
    sco_info['value'] = url
    return URL(**sco_info)


def _generate_sco_file(file_info):
    sco_file = []
    sco_info = {}
    sco_info['spec_version'] = "2.1"
    sco_info['id'] = "file--{}".format(uuid.uuid4())
    if file_info[0][1] == 0:
        sco_info['name'] = "dumped-file-{}".format(file_info[0][0])
    elif file_info[0][1] == 1:
        sco_info['name'] = "pcap-file-{}".format(file_info[0][0])
    else:
        sco_info['name'] = "unknown-file-{}".format(file_info[0][0])
    sco_info['hashes'] = {
        "MD5": file_info[0][2] 
    }
    if len(file_info[1]):
        sco_info['name'] = os.path.basename(file_info[1])
        sco_dir = _generate_sco_directory(os.path.dirname(file_info[1]))
        sco_info['parent_directory_ref'] = sco_dir.get('id')
        sco_file.append(sco_dir)
    sco_file.append(File(**sco_info))
    return sco_file


def _generate_sdo_malware(name, description, types):
    malware_info = {}
    malware_info['spec_version'] = "2.1"
    malware_info['id'] = "malware--{}".format(uuid.uuid4())
    malware_info['name'] = name
    malware_info['is_family'] = False
    malware_info['description'] = description
    malware_info['malware_types'] = types
    malware = Malware(**malware_info)
    return malware


def _create_observed_url_report(indicator, incident, wcfs):
    bundle = []
    for wcf in wcfs:
        sco_file = _generate_sco_url(wcf)
        bundle.append(sco_file)
        observed_data = _gen_sdo_opserved_data(incident, sco_file)
        bundle.append(observed_data)
        based_on = _gen_sro(incident[7], incident[8], 'based-on', indicator, observed_data)
        bundle.append(based_on)
        malware = _generate_sdo_malware('{}'.format(wcf), 
            'malicious url: {}'.format(wcf), [ 'backdoor', 'remote-access-trojan' ])
        indicates = _gen_sro(incident[7], incident[8], 'indicates', indicator, malware)
        bundle.append(malware)
        bundle.append(indicates)

    return bundle


def _create_observed_file_data_report(indicator, incident, dumps):
    bundle = []
    for _, dump in dumps.items():
        sco_file = _generate_sco_file(dump)
        bundle.extend(sco_file)
        observed_data = _gen_sdo_opserved_data(incident, sco_file[0])
        bundle.append(observed_data)
        based_on = _gen_sro(incident[7], incident[8], 'based-on', indicator, observed_data)
        bundle.append(based_on)
        if len(dump[0]) > 3 and dump[0][3]: # virus
            malware = _generate_sdo_malware(dump[0][0], 
                'virus file(id: {}; md5: {}, path: {})'.format(dump[0][0], dump[0][2], dump[1]),
                [ 'virus' ])
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


def _has_authentication_method(config):
    if config.get('user', None) and config.get('password', None):
        config['cert'] = None
        config['key'] = None
        return True
    if config.get('cert', None) and config.get('key', None):
        if os.path.exists(config.get('cert', None)) and os.path.exists(config.get('key', None)):
            config['user'] = None
            config['password'] = None
            return True

    return False


def get_config(config_file):
    config = {}
    if not os.path.exists(config_file):
        return None

    with open(config_file, mode='r') as f:
        config = json.load(f)

    if not config.get('api_root_url', None) or \
        not config.get('collection_id', None) or \
        not config.get('identity', None) or \
        not config.get('identity', None).get('id', None) or \
        not config.get('identity', None).get('name', None):
        _debug("Incorect stix configuration")
        logger.error("Incorect stix configuration")
        return None

    if not _has_authentication_method(config):
        _debug("Incorect stix configuration(no valid authentication method)")
        logger.error("Incorect stix configuration(no valid authentication method)")
        return None

    config['identity']['id'] = "identity--{}".format(config['identity']['id'])
    url = urlparse.urlparse(config['api_root_url'])
    config['server'] = url.hostname
    config['port'] = url.port
    config['protocol'] = url.scheme
    _debug('Parsed configuration: {}'.format(config))
    return config


def _report_incident(incident, output, config):
    envelope = []
    _debug('_report_incident(), using configuration: {}'.format(config))
    if config.get('enable', False) and config.get('api_root_url', None):
        taxii2 = Taxxi2Server(config['protocol'], config['server'], config['port'], config['user'], config['password'])
        api_root = taxii2.get_api_root(config.get('api_root_url', None))
        collection = api_root.get_collection(config['collection_id'])
    
    events = _get_events_by_incident(incident)
    dumps = {}
    if config.get('file_md5', False):
        dumps = _get_dump_files(events)
    wcfs = []
    if config.get('wcf', False):
        wcfs = _get_wcf_events(events)

    # 1. Create Identity
    if config.get('identity', None):
        identity = _create_identity(config['identity'])
        envelope.append(identity)

    # 2. Create Indicator
    indicator = _create_incident_report(incident, dumps, wcfs, identity.id)
    envelope.extend(indicator)

    # 3. Create Observed-Objects with SCOs
    if len(dumps):
        observed_data = _create_observed_file_data_report(indicator[0], incident, dumps)
        envelope.extend(observed_data)
    if len(wcfs):
        observed_data = _create_observed_url_report(indicator[0], incident, wcfs)
        envelope.extend(observed_data)

    if config.get('ips', False):
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
    _debug('Exports stix2 envelope:\n{}'.format(envelope.serialize(pretty=True)))
    if output:
        with open(output, 'a') as f:
            f.write(envelope.serialize(pretty=True))
    
    if config.get('enable', False):
        collection.add_bundle(envelope.serialize())
