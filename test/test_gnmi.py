import os
import yaml
import pytest
from nxos_gnmi.nxos_gnmi import Nexus
# content of test_sample.py


@pytest.fixture
def switches():
    config_dir = "./config/"
    config_files = os.listdir(config_dir)
    switches = []
    for sw_config in config_files:
        config_file = config_dir + sw_config
        with open(config_file) as config:
            config = yaml.load(config, Loader=yaml.FullLoader)
            host = config["mgmt_ip"]
            port = config["gnmi_port"]
            username = config["username"]
            password = os.environ["SWITCH_PASS"]
            cert = "./cert/gnmi.crt"

        switch = Nexus(host, port, username, password, cert, config)
        switches.append(switch)
    return switches


class TestGnmi():
    def test_vlan_status(self, switches):
        vlan_xpath = "/network-instances/network-instance/vlans/vlan/state/status"
        for sw in switches:
            res = sw.get_xpath(vlan_xpath, "STATE")
            for status in res:
                if "ACTIVE" != status:
                    assert False

    def test_interface_status(self, switches):
        int_xpath = "/interfaces/interface[name='{}']/state/admin-status"
        for sw in switches:
            for int_type in sw.config["interface"]:
                for int in sw.config["interface"][int_type]:
                    int_xpath = int_xpath.format(int["name"])
                    status = sw.get_xpath(int_xpath, "STATE")
                    if "UP" != status:
                        assert False

    def test_bgp_peer(self, switches):
        bgp_xpath = "/network-instances/network-instance[name='default']/protocols/protocol/bgp/neighbors/neighbor/state"
        for sw in switches:
            peers_state = sw.get_xpath(bgp_xpath, "ALL")
            if type(peers_state) is dict: 
                if peers_state["session-state"] != "ESTABLISHED":
                    print(peers_state)
                    assert False
                else:
                    continue

            for state in peers_state:
                if state["session-state"] != "ESTABLISHED":
                    print(state)
                    assert False
