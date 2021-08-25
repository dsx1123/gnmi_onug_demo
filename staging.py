#!/usr/bin/env python3
import os
import sys
import yaml
import logging
from nxos_gnmi.nxos_gnmi import Nexus


logger = logging.getLogger(__name__)
c_handler = logging.StreamHandler(sys.stdout)
c_handler.setLevel(logging.DEBUG)
c_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)


config_dir = "./config/"
config_files = os.listdir(config_dir)

if __name__ == "__main__":
    for sw_config in config_files:
        config_file = config_dir + sw_config
        with open(config_file) as config:
            config = yaml.load(config, Loader=yaml.FullLoader)

        host = config["mgmt_ip"]
        port = config["gnmi_port"]
        username = config["username"]
        password = os.environ["SWITCH_PASS"]
        cert = "./cert/gnmi.crt"
        logger.info("start to provision switches")
        switch = Nexus(host, port, username, password, cert, config)
        res = switch.prov_sys()
        res = switch.prov_int()
        res = switch.prov_vlan()
        res = switch.prov_rt_policy()
        res = switch.prov_bgp()
