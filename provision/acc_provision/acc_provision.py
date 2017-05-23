#!/usr/bin/env python

from __future__ import print_function

import argparse
import base64
import json
import pkgutil
import socket
import struct
import sys
import yaml


from OpenSSL import crypto
from apic_provision import Apic, ApicKubeConfig
from jinja2 import Environment, PackageLoader
from os.path import exists


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
            "system_id": None,
            "vrf": {
                "name": None,
                "tenant": None,
            },
            "l3out": {
                "name": None,
                "external_networks": None,
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
            "node_subnet": None,
            "pod_subnet": None,
            "extern_dynamic": None,
            "extern_static": None,
            "node_svc_subnet": None,
            "kubeapi_vlan": None,
            "service_vlan": None,
            "infra_vlan": 4093,
        },
        "kube_config": {
            "controller": "1.1.1.1",
            "use_tolerations": True,
            "use_cluster_role": True,
            "use_ds_rolling_update": True,
            "image_pull_policy": "Always",
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
        if config_file == "-":
            info("Loading configuration from \"STDIN\"")
            config = yaml.load(sys.stdin)
        else:
            info("Loading configuration from \"%s\"" % config_file)
            with open(config_file, 'r') as file:
                config = yaml.load(file)
    if config is None:
        config = {}
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
                "password": "ToBeFixed!",
                "certfile": "user-%s.crt" % system_id,
                "keyfile": "user-%s.key" % system_id,
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
    get = lambda t: reduce(lambda x, y: x and x.get(y), t, config)

    checks = {
        "system_id": (get(("aci_config", "system_id")), required),
        "aep": (get(("aci_config", "aep")), required),
        "vrf-name": (get(("aci_config", "vrf", "name")), required),
        "vrf-tenant": (get(("aci_config", "vrf", "tenant")), required),
        "l3out-name": (get(("aci_config", "l3out", "name")), required),
        "l3out-external-network":
            (get(("aci_config", "l3out", "external_networks")), required),
        "apic_host": (get(("aci_config", "apic_hosts")), required),
        "uplink_if": (get(("node_config", "uplink_iface")), required),
        "vxlan_if": (get(("node_config", "vxlan_uplink_iface")), required),
        "node_subnet": (get(("net_config", "node_subnet")), required),
        "pod_subnet": (get(("net_config", "pod_subnet")), required),
        "extern_dynamic": (get(("net_config", "extern_dynamic")), required),
        "extern_static": (get(("net_config", "extern_static")), required),
        "node_svc_subnet": (get(("net_config", "node_svc_subnet")), required),
        "kubeapi_vlan": (get(("net_config", "kubeapi_vlan")), required),
        "service_vlan": (get(("net_config", "service_vlan")), required),
        "infra_vlan": (get(("net_config", "infra_vlan")), required),
    }

    if get(("provision", "prov_apic")) is not None:
        checks.update({
            "apic_username":
                (get(("aci_config", "apic_login", "username")), required),
            "apic_password":
                (get(("aci_config", "apic_login", "password")), required),
        })

    ret = True
    for k in checks:
        value, validator = checks[k]
        try:
            if not validator(value):
                raise Exception(k)
        except Exception as e:
            err("Required configuration not present or not correct: '%s'"
                % e.message)
            ret = False
    return ret


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


def generate_sample(filep):
    data = pkgutil.get_data('acc_provision', 'provision-config.yaml')
    print(data, file=filep)
    return filep


def generate_cert(username, cert_file, key_file):
    if not exists(cert_file) or not exists(key_file):
        # Do not overwrite previously generated data if it exists

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().O = "Cisco Systems"
        cert.get_subject().CN = "User %s" % username
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
        with open(cert_file, "wt") as certp:
            certp.write(cert_data)
        with open(key_file, "wt") as keyp:
            keyp.write(key_data)
        return cert_data


def generate_kube_yaml(config, output):
    env = Environment(
        loader=PackageLoader('acc_provision', 'templates'),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters['base64enc'] = base64.b64encode
    env.filters['json'] = json_indent
    env.filters['yaml_quote'] = yaml_quote
    template = env.get_template('aci-containers.yaml')

    if output:
        if output == "-":
            info("Writing kubernetes infrastructure YAML to \"STDOUT\"")
            template.stream(config=config).dump(sys.stdout)
        else:
            info("Writing kubernetes infrastructure YAML to \"%s\"" % output)
            template.stream(config=config).dump(output)
    return config


def generate_apic_config(config, prov_apic, apic_file):
    apic_config = ApicKubeConfig(config).get_config()
    if apic_file:
        if apic_file == "-":
            info("Writing apic configuration to \"STDOUT\"")
            ApicKubeConfig.save_config(apic_config, sys.stdout)
        else:
            info("Writing apic configuration to \"%s\"" % apic_file)
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
    debug = config["provision"]["debug_apic"]
    apic = Apic(apic_host, apic_username, apic_password, debug=debug)
    return apic


def parse_args():
    parser = argparse.ArgumentParser(
        description='Provision an ACI kubernetes installation'
    )
    parser.add_argument(
        '-c', '--config', default="-", metavar='',
        help='Input file with your fabric configuration')
    parser.add_argument(
        '-o', '--output', default="-", metavar='',
        help='Output file for your kubernetes deployment')
    parser.add_argument(
        '-a', '--apic', action='store_true', default=False,
        help='Create/Validate the required APIC resources')
    parser.add_argument(
        '-d', '--delete', action='store_true', default=False,
        help='Delete the APIC resources that would have be created')
    parser.add_argument(
        '-s', '--sample', action='store_true', default=False,
        help='Print a sample input file with fabric configuration')
    parser.add_argument(
        '-u', '--username', default=None, metavar='',
        help='APIC admin username to use for APIC API access')
    parser.add_argument(
        '-p', '--password', default=None, metavar='',
        help='APIC admin password to use for APIC API access')
    parser.add_argument(
        '-v', '--verbose', action='store_true', default=False,
        help='Enable debug')
    return parser.parse_args()


def main(args=None, apic_file=None):
    # args, apic_file are set by the test functions
    if args is None:
        args = parse_args()
    config_file = args.config
    output_file = args.output
    prov_apic = None
    if args.apic:
        prov_apic = True
        if args.delete:
            prov_apic = False

    # Print sample, if needed
    if args.sample:
        generate_sample(sys.stdout)
        return True

    # command line config
    config = {
        "aci_config": {
            "apic_login": {
            }
        },
        "provision": {
            "prov_apic": prov_apic,
            "debug_apic": args.verbose,
        },
    }
    if args.username:
        config["aci_config"]["apic_login"]["username"] = args.username
    if args.password:
        config["aci_config"]["apic_login"]["password"] = args.password

    # Create config
    default_config = config_default()
    user_config = config_user(config_file)
    deep_merge(config, user_config)
    deep_merge(config, default_config)

    # Validate config
    if not config_validate(config):
        err("Please fix configuration and retry.")
        return False

    # Adjust config based on convention/apic data
    adj_config = config_adjust(config, prov_apic)
    deep_merge(config, adj_config)
    config["net_config"]["infra_vlan"] = \
        adj_config["net_config"]["infra_vlan"]

    # Advisory checks, including apic checks, ignore failures
    if not config_advise(config, prov_apic):
        pass

    # generate output files; and program apic if needed
    username = config["aci_config"]["aim_login"]["username"]
    certfile = config["aci_config"]["aim_login"]["certfile"]
    keyfile = config["aci_config"]["aim_login"]["keyfile"]
    generate_cert(username, certfile, keyfile)
    generate_apic_config(config, prov_apic, apic_file)
    generate_kube_yaml(config, output_file)
    return True


if __name__ == "__main__":
    main()
