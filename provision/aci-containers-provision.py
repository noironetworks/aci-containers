#!/usr/bin/env python

from __future__ import print_function

import argparse
import base64
import filecmp
import glob
import hashlib
import json
import os
import socket
import struct
import sys
import yaml


from apic import Apic, ApicKubeConfig
from jinja2 import Environment, PackageLoader


def info(msg):
    print("INFO: " + msg, file=sys.stderr)


def warn(msg):
    print("WARN: " + msg, file=sys.stderr)


def err(msg):
    print("ERR:  " + msg, file=sys.stderr)


def json_indent(s):
    return json.dumps(s, indent=4)


def yaml_quote(s):
    return "'%s'" % str(s).replace("'", "''")


def deep_merge(user, default):
    if isinstance(user, dict) and isinstance(default, dict):
        for k, v in default.iteritems():
            if k not in user:
                user[k] = v
            else:
                user[k] = deep_merge(user[k], v)
    return user


def config_default():
    # Default values for configuration
    default_config = {
        "aci_config": {
            "system_id": "kube",
            "vrf": {
                "name": "kube",
                "tenant": "common",
            },
            "l3out": {
                "name": "l3out",
                "external_networks": ["default"],
            },
            "vmm_domain": {
                "encap_type": "vxlan",
                "mcast_fabric": "225.1.2.3",
                "mcast_range": {
                    "start": "225.2.1.1",
                    "end": "225.2.255.255",
                },
            },
            "client_cert": False,
            "client_ssl": True,
        },
        "net_config": {
            "node_subnet": "10.1.0.1/16",
            "pod_subnet": "10.2.0.1/16",
            "extern_dynamic": "10.3.0.1/24",
            "extern_static": "10.4.0.1/24",
            "node_svc_subnet": "10.5.0.1/24",
            "kubeapi_vlan": 4001,
            "service_vlan": 4003,
            "infra_vlan": 4093,
        },
        "kube_config": {
            "controller": "1.1.1.1",
            "use_cluster_role": True,
            "use_ds_rolling_update": True,
        },
        "registry": {
            "image_prefix": "noiro",
        },
        "logging": {
            "controller_log_level": "info",
            "hostagent_log_level": "info",
            "opflexagent_log_level": "info",
            "aim_debug": "False",
        },
    }
    return default_config


def config_user(config_file):
    config = {}
    if config_file:
        if config_file == "_":
            info("Loading configuration from \"STDIN\"")
            config = yaml.load(sys.stdin)
        else:
            info("Loading configuration from \"%s\"" % config_file)
            with open(config_file, 'r') as file:
                config = yaml.load(file)
    return config


def cidr_split(cidr):
    ip2int = lambda a: struct.unpack("!I", socket.inet_aton(a))[0]
    int2ip = lambda a: socket.inet_ntoa(struct.pack("!I", a))
    rtr, mask = cidr.split('/')
    maskbits = int('1' * (32 - int(mask)), 2)
    rtri = ip2int(rtr)
    starti = rtri + 1
    endi = (rtri | maskbits) - 1
    subi = (rtri & (0xffffffff ^ maskbits))
    return int2ip(starti), int2ip(endi), rtr, int2ip(subi), mask


def config_adjust(config, prov_apic):
    apic = None
    if prov_apic is not None:
        apic = get_apic(config)

    system_id = config["aci_config"]["system_id"]
    infra_vlan = config["net_config"]["infra_vlan"]
    if apic is not None:
        infra_vlan = apic.get_infravlan()

    pod_subnet = config["net_config"]["pod_subnet"]
    extern_dynamic = config["net_config"]["extern_dynamic"]
    extern_static = config["net_config"]["extern_static"]
    node_svc_subnet = config["net_config"]["node_svc_subnet"]
    encap_type = config["aci_config"]["vmm_domain"]["encap_type"]
    tenant = system_id

    adj_config = {
        "aci_config": {
            "cluster_tenant": tenant,
            "physical_domain": {
                "domain": system_id + "-pdom",
                "vlan_pool": system_id + "-pool",
            },
            "vmm_domain": {
                "domain": system_id,
                "controller": system_id,
                "mcast_pool": system_id + "-mpool",
            },
            "aim_login": {
                "username": system_id,
                # Tmp hack, till I generate certificates
                "password": hashlib.md5(system_id).hexdigest(),
                "certfile": None,
            },
        },
        "net_config": {
            "infra_vlan": infra_vlan,
        },
        "node_config": {
            "encap_type": encap_type,
        },
        "kube_config": {
            "default_endpoint_group": {
                "tenant": tenant,
                "app_profile": "kubernetes",
                "group": "kube-default",
            },
            "namespace_default_endpoint_group": {
                "kube-system": {
                    "tenant": tenant,
                    "app_profile": "kubernetes",
                    "group": "kube-system",
                },
            },
            "pod_ip_pool": [
                {
                    "start": cidr_split(pod_subnet)[0],
                    "end": cidr_split(pod_subnet)[1],
                }
            ],
            "pod_network": [
                {
                    "subnet": "%s/%s" % cidr_split(pod_subnet)[3:],
                    "gateway": cidr_split(pod_subnet)[2],
                    "routes": [
                        {
                            "dst": "0.0.0.0/0",
                            "gw": cidr_split(pod_subnet)[2],
                        }
                    ],
                },
            ],
            "service_ip_pool": [
                {
                    "start": cidr_split(extern_dynamic)[0],
                    "end": cidr_split(extern_dynamic)[1],
                },
            ],
            "static_service_ip_pool": [
                {
                    "start": cidr_split(extern_static)[0],
                    "end": cidr_split(extern_static)[1],
                },
            ],
            "node_service_ip_pool": [
                {
                    "start": cidr_split(node_svc_subnet)[0],
                    "end": cidr_split(node_svc_subnet)[1],
                },
            ],
            "node_service_gw_subnets": [
                node_svc_subnet,
            ],
        },
    }
    return adj_config


def config_validate(config):
    required = lambda x: x
    try:
        checks = {
            "system_id": (config["aci_config"]["system_id"], required),
            "aep": (config["aci_config"]["aep"], required),
            "apic_host": (config["aci_config"]["apic_hosts"][0], required),
            "apic_username": (config["aci_config"]["apic_login"]["username"], required),
            "apic_password": (config["aci_config"]["apic_login"]["password"], required),
            "uplink_if": (config["node_config"]["uplink_iface"], required),
            "vxlan_if": (config["node_config"]["vxlan_uplink_iface"], required),
            "kubeapi_vlan": (config["net_config"]["kubeapi_vlan"], required),
            "service_vlan": (config["net_config"]["service_vlan"], required),
        }
        for k in checks:
            value, validator = checks[k]
            if not validator(value):
                raise Exception(k)
    except Exception as e:
        err("Required configuration not present or not correct: '%s'" % e.message)
        return False
    return True


def config_advise(config, prov_apic):
    try:
        if prov_apic is not None:
            apic = get_apic(config)

            aep_name = config["aci_config"]["aep"]
            aep = apic.get_aep(aep_name)
            if aep is None:
                warn("AEP not defined in the APIC: %s" % aep_name)

            vrf_tenant = config["aci_config"]["vrf"]["tenant"]
            vrf_name = config["aci_config"]["vrf"]["name"]
            l3out_name = config["aci_config"]["l3out"]["name"]
            vrf = apic.get_vrf(vrf_tenant, vrf_name)
            if vrf is None:
                warn("VRF not defined in the APIC: %s/%s" %
                     (vrf_tenant, vrf_name))
            l3out = apic.get_l3out(vrf_tenant, l3out_name)
            if l3out is None:
                warn("L3out not defined in the APIC: %s/%s" %
                     (vrf_tenant, l3out_name))

    except Exception as e:
        warn("Error in validating existence of AEP: '%s'" % e.message)
    return True


def generate_kube_yaml(config, output):
    env = Environment(
        loader=PackageLoader('aci-containers-provision', 'templates'),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters['base64enc'] = base64.b64encode
    env.filters['json'] = json_indent
    env.filters['yaml_quote'] = yaml_quote
    template = env.get_template('aci-containers.yaml')

    info("Writing kubernetes infrastructure YAML to \"%s\"" % output)
    template.stream(config=config).dump(output)
    return config


def generate_apic_config(config, prov_apic, apic_file):
    apic_config = ApicKubeConfig(config).get_config()
    if apic_file:
        if apic_file == "-":
            info("Writing kubernetes configuration to \"STDOUT\"")
            ApicKubeConfig.save_config(apic_config, sys.stdout)
        else:
            info("Writing kubernetes configuration to \"%s\"" % apic_file)
            with open(apic_file, 'w') as outfile:
                ApicKubeConfig.save_config(apic_config, outfile)

    if prov_apic is not None:
        apic = get_apic(config)
        if prov_apic is True:
            apic.provision(apic_config)
        if prov_apic is False:
            apic.unprovision(apic_config)
    return apic_config


def get_apic(config):
    apic_host = config["aci_config"]["apic_hosts"][0]
    apic_username = config["aci_config"]["apic_login"]["username"]
    apic_password = config["aci_config"]["apic_login"]["password"]
    apic = Apic(apic_host, apic_username, apic_password)
    return apic


def parse_args():
    parser = argparse.ArgumentParser(
        description='Provision an ACI kubernetes installation'
    )
    parser.add_argument('-c', '--config', default="-", metavar='',
                        help='Input file with your fabric configuration')
    parser.add_argument('-o', '--output', default="-", metavar='',
                        help='Output file for your kubernetes deployment')
    parser.add_argument('-a', '--apic', action='store_true', default=False,
                        help='Execute the required APIC configuration as well')
    parser.add_argument('-u', '--unprovision', action='store_true', default=False,
                        help='Unprovision the APIC resources')
    return parser.parse_args()


def main(config_file, output_file, prov_apic=True, apic_file=None):
    # Create config
    default_config = config_default()
    config = config_user(config_file)
    deep_merge(config, default_config)

    # Validate config
    if not config_validate(config):
        err("Please fix configuration and retry.")
        return None

    # Adjust config based on convention/apic data
    adj_config = config_adjust(config, prov_apic)
    deep_merge(config, adj_config)
    config["net_config"]["infra_vlan"] = \
        adj_config["net_config"]["infra_vlan"]

    # Advisory checks, including apic checks, ignore failures
    if not config_advise(config, prov_apic):
        pass

    # generate output files; and program apic if needed
    generate_apic_config(config, prov_apic, apic_file)
    generate_kube_yaml(config, output_file)


def test_main():
    for inp in glob.glob("tests/*.inp.yaml"):
        kubefile = os.tempnam(".", "tmp-kube-")
        apicfile = os.tempnam(".", "tmp-apic-")
        main(inp, kubefile, prov_apic=None, apic_file=apicfile)
        expectedkube = inp[:-8] + 'out.yaml'
        assert filecmp.cmp(kubefile, expectedkube)
        expectedapic = inp[:-8] + 'apic.txt'
        assert filecmp.cmp(apicfile, expectedapic)
        os.remove(kubefile)
        os.remove(apicfile)

if __name__ == "__main__":
    args = parse_args()
    prov_apic = None
    if args.apic:
        prov_apic = True
        if args.unprovision:
            prov_apic = False
    main(args.config, args.output, prov_apic=prov_apic)
