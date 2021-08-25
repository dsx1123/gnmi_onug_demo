import sys
import json
import logging
from cisco_gnmi import ClientBuilder
from google.protobuf import json_format
from grpc import RpcError

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
c_handler = logging.StreamHandler(sys.stdout)
c_handler.setLevel(logging.DEBUG)
c_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)


class NxosGnmi():
    OC_IF = "openconfig-interfaces:interfaces"
    OC_NETWORK = "openconfig-network-instance:network-instances"
    OC_RT_POLICY = "openconfig-routing-policy:routing-policy"

    def __init__(self, host, port, username, password, cert):
        self.target = '{}:{}'.format(host, port)
        self.username = username
        self.password = password
        self.cert = cert

        self.client = (
            ClientBuilder(self.target)
            .set_os('NX-OS')
            .set_secure_from_file(self.cert)
            .set_ssl_target_override()
            .set_call_authentication(self.username, self.password)
            .construct()
        )
        self.caps = json.loads(json_format.MessageToJson(self.client.capabilities()))

    def get_xpath(self, xpath, data_type="CONFIG"):
        res = self.client.get_xpaths(xpath, data_type)
        json_val = res.notification[0].update[0].val.json_val.decode('ascii')
        if json_val:
            return json.loads(json_val)
        else:
            return json_val

    def set_from_json(self, update_data):
        response = self.client.set_json(update_json_configs=update_data)
        return(response)

    def delete_xpath(self, xpath):
        return self.client.delete_xpaths(xpath)


class Nexus(NxosGnmi):
    DEVICE = "Cisco-NX-OS-device:System"

    def __init__(self, host, port, username, password, cert, config):
        super().__init__(host, port, username, password, cert)
        self.config = config

    def config_hostname(self):
        hostname_payload = {
            Nexus.DEVICE: {
                "name": self.config["hostname"]
            }
        }
        logger.info("set hostnam of swtich {} to {}".format(self.config["hostname"], self.config["hostname"]))
        res = self.set_from_json(json.dumps(hostname_payload))
        return res

    def config_ntp(self):
        ntp_payload = {
            Nexus.DEVICE: {
                "time-items": {
                    "prov-items": {
                        "NtpProvider-list": []
                    }
                }
            }
        }

        for ntp in self.config["ntp"]:
            ntp_item = {
                "name": ntp["server"],
                "preferred": ntp.get("prefer", False),
                "provT": "server",
                "vrf": ntp["vrf"]
            }
            ntp_payload[Nexus.DEVICE]["time-items"]["prov-items"]["NtpProvider-list"].append(ntp_item)
        logger.info("set ntp sever to {}".format(self.config["ntp"]))
        res = self.set_from_json(json.dumps(ntp_payload))
        return res

    def config_feature(self):
        feature_payload = {
            "Cisco-NX-OS-device:System": {
                "fm-items": {
                }
            }
        }
        for feature in self.config['feature']:
            key = feature + '-items'
            feature_payload[Nexus.DEVICE]['fm-items'][key] = {'adminSt': 'enabled'}
        logger.info("enable feautres: {}".format(self.config["feature"]))
        res = self.set_from_json(json.dumps(feature_payload))
        return res

    def init_int(self):
        int_payload = {
            Nexus.OC_IF: {
                "interface": []
            }
        }

        for type in self.config["interface"]:
            for int in self.config["interface"][type]:
                int_item = {"name": int["name"]}
                int_payload[Nexus.OC_IF]["interface"].append(int_item)
        res = self.set_from_json(json.dumps(int_payload))

        # init trunk interface if needed
        for int in self.config["interface"]["trunk"]:
            mode_xpath = "/interfaces/interface[name='{}']/ethernet/switched-vlan/config/interface-mode".format(int["name"])
            mode = self.get_xpath(mode_xpath)
            if mode == "TRUNK":
                continue
            trunk_payload = {
                Nexus.OC_IF: {
                    "interface": [
                        {
                            "name": int["name"],
                            'ethernet': {
                                'switched-vlan': {
                                    'config': {
                                        'access-vlan': 1,
                                        'interface-mode': 'TRUNK',
                                        'native-vlan': 1,
                                    }
                                }
                            }
                        }
                    ]
                }
            }
            res = self.set_from_json(json.dumps(trunk_payload))
            trunk_xpath = "/interfaces/interface[name='{}']/ethernet/switched-vlan/config/trunk-vlans".format(int["name"])
            res = self.delete_xpath(trunk_xpath)
        return res

    def config_int_lo(self):
        lo_payload = {
            Nexus.OC_IF: {
                "interface": []
            }
        }
        for int in self.config["interface"]["loopback"]:
            looback_item = {
                "name": int["name"],
                'subinterfaces': {
                    'subinterface': [
                        {
                            'config': {'index': 0},
                            'index': 0,
                            'ipv4': {
                                'addresses': {
                                    'address': [
                                        {
                                            'config': {
                                                'ip': int["ipv4"].split("/")[0],
                                                'prefix-length': int["ipv4"].split("/")[1]},
                                            'ip': int["ipv4"].split("/")[0]
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
            lo_payload[Nexus.OC_IF]["interface"].append(looback_item)
        logger.info("create loopback interfaces: {}".format(self.config["interface"]["loopback"]))
        res = self.set_from_json(json.dumps(lo_payload))
        return res

    def config_int_rtd(self):
        # OC YANG doesn't support changing port to l3
        rtd_payload = {
            Nexus.DEVICE: {
                "intf-items": {
                    "phys-items": {
                        "PhysIf-list": []
                    }
                }
            }
        }
        for int in self.config["interface"]["routed"]:
            rtd_item = {
                "id": int["name"],
                "layer": "Layer3",
                "adminSt": "up"
            }
            rtd_payload[Nexus.DEVICE]["intf-items"]["phys-items"]["PhysIf-list"].append(rtd_item)
        logger.info("change interface to layer3 {}".format([i["name"] for i in self.config["interface"]["routed"]]))
        res = self.set_from_json(json.dumps(rtd_payload))

        rtd_payload = {
            Nexus.OC_IF: {
                "interface": []
            }
        }
        for int in self.config["interface"]["routed"]:
            rtd_item = {
                "name": int["name"],
                'subinterfaces': {
                    'subinterface': [
                        {
                            'config': {'index': 0},
                            'index': 0,
                            'ipv4': {
                                'addresses': {
                                    'address': [
                                        {
                                            'config': {
                                                'ip': int["ipv4"].split("/")[0],
                                                'prefix-length': int["ipv4"].split("/")[1]},
                                            'ip': int["ipv4"].split("/")[0]
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
            rtd_payload[Nexus.OC_IF]["interface"].append(rtd_item)
        logger.info("update ip of routed interfaces: {}".format(self.config["interface"]["routed"]))
        res = self.set_from_json(json.dumps(rtd_payload))
        return res

    def config_int_trunk(self):
        # First need get existed vlan then add new
        existed_vlan = {}
        for int in self.config["interface"]["trunk"]:
            xpath = "/interfaces/interface[name='{}']/ethernet/switched-vlan/config/trunk-vlans".format(int['name'])
            trunk_vlans = self.get_xpath(xpath)
            existed_vlan[int['name']] = trunk_vlans

        trunk_payload = {
            Nexus.OC_IF: {
                "interface": []
            }
        }

        for int in self.config["interface"]["trunk"]:
            add_vlan = list(set(int["vlan"]) - set(existed_vlan[int["name"]]))
            if not add_vlan:
                continue
            trunk_item = {
                "name": int["name"],
                'ethernet': {
                    'switched-vlan': {
                        'config': {
                            'access-vlan': 1,
                            'interface-mode': 'TRUNK',
                            'native-vlan': 1,
                            'trunk-vlans': add_vlan
                        }
                    }
                }
            }
            trunk_payload[Nexus.OC_IF]["interface"].append(trunk_item)
        logger.info("trunking desired vlan on interfaces: {}".format(self.config["interface"]["trunk"]))
        res = self.set_from_json(json.dumps(trunk_payload))
        return res

    def config_int_svi(self):
        svi_payload = {
            Nexus.OC_IF: {
                "interface": []
            }
        }
        for int in self.config["interface"]["svi"]:
            svi_item = {
                "name": int["name"],
                "config": {"enabled": True},
                "routed-vlan": {
                    'config': {'vlan': int["vlan_id"]},
                    'ipv4': {
                        'addresses': {
                            'address': [
                                {
                                    'config': {
                                        'ip': int["ipv4"].split("/")[0],
                                        'prefix-length': int["ipv4"].split("/")[1]},
                                    'ip': int["ipv4"].split("/")[0]
                                }
                            ]
                        }
                    }
                }
            }
            svi_payload[Nexus.OC_IF]["interface"].append(svi_item)
        logger.info("create SVI interfaces: {}".format([i["name"] for i in self.config["interface"]["svi"]]))
        res = self.set_from_json(json.dumps(svi_payload))
        return res

    def config_pfx_list(self):
        pfx_list_payload = {
            Nexus.OC_RT_POLICY: {
                'defined-sets': {
                    'prefix-sets': {
                        'prefix-set': []
                    }
                }
            }
        }
        for pfx_list in self.config["prefix_list"]:
            pfx_list_item = {
                'config': {
                    'mode': 'IPV4',
                    'name': 'connected'
                },
                'name': pfx_list["name"],
                'prefixes': {
                    'prefix': []
                }
            }
            for pfx in pfx_list["prefix"]:
                pfx_item = {
                    'ip-prefix': pfx,
                    'masklength-range': 'exact'
                }
                pfx_list_item["prefixes"]["prefix"].append(pfx_item)
            pfx_list_payload[Nexus.OC_RT_POLICY]["defined-sets"]["prefix-sets"]["prefix-set"].append(pfx_list_item)
        logger.info("create prefix lists: {}".format([p["name"] for p in self.config["prefix_list"]]))
        res = self.set_from_json(json.dumps(pfx_list_payload))
        return res

    def config_rt_map(self):
        rt_map_payload = {
            Nexus.OC_RT_POLICY: {
                'policy-definitions': {
                    "policy-definition": []
                }
            }
        }
        for rt_map in self.config["route_map"]:
            rt_item = {
                "name": rt_map["name"],
                "statements": {
                    'statement': []
                }
            }
            for seq in rt_map["match"]:
                seq_item = {
                    "name": seq["seq"],
                    "actions": {
                        'config': {
                            'policy-result': 'ACCEPT_ROUTE'
                        }
                    },
                    'conditions': {
                        'match-prefix-set': {
                            'config': {
                                'match-set-options': seq["action"],
                                'prefix-set': seq["ip_prefix"]
                            }
                        }
                    }
                }
                rt_item["statements"]["statement"].append(seq_item)
            rt_map_payload[Nexus.OC_RT_POLICY]["policy-definitions"]["policy-definition"].append(rt_item)
        logger.info("create route-maps: {}".format([p["name"] for p in self.config["route_map"]]))
        res = self.set_from_json(json.dumps(rt_map_payload))
        return res

    def prov_sys(self):
        logger.info("provisoining system configuration on switch {}".format(self.config["hostname"]))
        try:
            self.config_hostname()
            self.config_ntp()
            self.config_feature()
        except RpcError as e:
            logger.error(e)

    def prov_int(self):
        logger.info("provisoining inteface configuration on switch {}".format(self.config["hostname"]))
        try:
            self.init_int()
            self.config_int_lo()
            self.config_int_rtd()
            self.config_int_trunk()
            self.config_int_svi()
        except RpcError as e:
            logger.error(e)

    def prov_vlan(self):
        logger.info("provisoining vlan {} on switch {}".format([v["name"] for v in self.config["vlan"]], self.config["hostname"]))
        vlan_payload = {
            Nexus.OC_NETWORK: {
                "network-instance": [
                    {
                        "name": "default",
                        "vlans": {
                            "vlan": []
                        }
                    }
                ]
            }
        }
        for vlan in self.config["vlan"]:
            vlan_item = {
                'config': {
                    'name': vlan["name"],
                    'status': 'ACTIVE',
                    'vlan-id': vlan["id"]
                },
                'vlan-id': vlan["id"]
            }
            vlan_payload[Nexus.OC_NETWORK]["network-instance"][0]["vlans"]["vlan"].append(vlan_item)
        res = self.set_from_json(json.dumps(vlan_payload))
        return res

    def prov_bgp(self):
        # configure as and router id first
        logger.info("provisoining bgp configuration on switch {}".format(self.config["hostname"]))
        bgp_payload = {
            Nexus.OC_NETWORK: {
                "network-instance": [
                    {
                        "name": "default",
                        'protocols': {
                            'protocol': [
                                {
                                    'bgp': {
                                        'global': {
                                            'afi-safis': {
                                                'afi-safi': [
                                                    {
                                                        'afi-safi-name': 'IPV4_UNICAST',
                                                        'config': {'afi-safi-name': 'IPV4_UNICAST'}
                                                    }
                                                ]
                                            },
                                            'config': {
                                                'as': self.config["bgp"]["as"],
                                                'router-id': self.config["bgp"]["rtr_id"]
                                            }
                                        }
                                    },
                                    'identifier': 'BGP',
                                    'name': 'bgp'
                                }
                            ]
                        }
                    }
                ]
            }
        }
        logger.info("create bgp process with as {}".format(self.config["bgp"]["as"]))
        res = self.set_from_json(json.dumps(bgp_payload))

        # add neighbor to af ipv4 unicast ipv4
        bgp_payload[Nexus.OC_NETWORK]["network-instance"][0]["protocols"]["protocol"][0]["bgp"]["neighbors"] = {
            "neighbor": []
        }
        for neighbor in self.config["bgp"]["neighbor"]:
            neighbor_item = {
                'afi-safis': {
                    'afi-safi': [
                        {
                            'afi-safi-name': 'IPV4_UNICAST',
                            'config': {'afi-safi-name': 'IPV4_UNICAST'}
                        }
                    ]
                },
                'config': {
                    'neighbor-address': neighbor["peer"],
                    'peer-as': neighbor["peer_as"]
                },
                'neighbor-address': neighbor["peer"],
            }
            bgp_payload[Nexus.OC_NETWORK]["network-instance"][0]["protocols"]["protocol"][0]["bgp"]["neighbors"]["neighbor"].append(neighbor_item)
        logger.info("create bgp neighbors: {}".format(self.config["bgp"]["neighbor"]))
        res = self.set_from_json(json.dumps(bgp_payload))

        # redistribution
        redis_payload = {
            Nexus.DEVICE: {
                "bgp-items": {
                    "name": "bgp",
                    "inst-items": {
                        "name": "bgp",
                        'dom-items': {
                            'Dom-list': [
                                {
                                    'name': 'default',
                                    'af-items': {
                                        'DomAf-list': [
                                            {
                                                'type': 'ipv4-ucast',
                                                'interleak-items': {
                                                    'InterLeakP-list': [
                                                        {
                                                            "asn": "none",
                                                            "inst": "none",
                                                            'proto': self.config["bgp"]["redistribution"]["type"],
                                                            'rtMap': self.config["bgp"]["redistribution"]["rt_map"],
                                                            'scope': 'inter'
                                                        }
                                                    ]
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
        logger.info("redistribute connected network with route-map: {}".format(self.config["bgp"]["redistribution"]["rt_map"]))
        res = self.set_from_json(json.dumps(redis_payload))
        return res

    def prov_rt_policy(self):
        try:
            self.config_pfx_list()
            self.config_rt_map()
        except RpcError as e:
            logger.error(e)
