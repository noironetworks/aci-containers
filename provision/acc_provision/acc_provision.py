#!/usr/bin/env python

from __future__ import print_function, unicode_literals

import argparse
import base64
import copy
import functools
import ipaddress
import json
import os
import os.path
import random
import string
import sys
import uuid

import pkg_resources
import pkgutil
import yaml

from OpenSSL import crypto
from .apic_provision import Apic, ApicKubeConfig
from jinja2 import Environment, PackageLoader
from os.path import exists

DEFAULT_FLAVOR = "kubernetes-1.10"

VERSION_FIELDS = [
    "cnideploy_version",
    "aci_containers_host_version",
    "opflex_agent_version",
    "aci_containers_controller_version",
    "openvswitch_version",
]

VERSIONS = {
    "1.6": {
        "cnideploy_version": "1.6r15",
        "aci_containers_host_version": "1.6r15",
        "aci_containers_controller_version": "1.6r15",
        "opflex_agent_version": "1.6r22",
        "openvswitch_version": "1.6r12",
    },
    "1.7": {
        "cnideploy_version": "1.7r86",
        "aci_containers_host_version": "1.7r86",
        "aci_containers_controller_version": "1.7r86",
        "opflex_agent_version": "1.7r70",
        "openvswitch_version": "1.7r24",
    },
    "1.9": {
        "cnideploy_version": "1.9r30",
        "aci_containers_host_version": "1.9r30",
        "aci_containers_controller_version": "1.9r30",
        "opflex_agent_version": "1.9r35",
        "openvswitch_version": "1.7r24",
    },
}

# Known Flavor options:
# - template_generator: Function that generates the output config
#       file. Default: generate_kube_yaml.
# - version_fields: List of config options that must be specified for
#       the specific version of deployment. Default: VERSION_FIELDS.
# - vip_pool_required: Whether virtual IP pool needs to be specified.
#       Default: False.
# - apic: Dict that is used for configuring ApicKubeConfig
#       Known sub-options:
#       - use_kubeapi_vlan: Whether kubeapi_vlan should be used. Default: True.
#       - tenant_generator: Name of the function to generate tenant objects.
#             Default: kube_tn.
#       - associate_aep_to_nested_inside_domain: Whether AEP should be attached
#             to nested_inside domain. Default: False.
KubeFlavorOptions = {}

CfFlavorOptions = {
    'apic': {
        'use_kubeapi_vlan': False,
        'tenant_generator': 'cloudfoundry_tn',
        'associate_aep_to_nested_inside_domain': True,
    },
    'version_fields': [],
    'vip_pool_required': True,
}

DEFAULT_FLAVOR_OPTIONS = KubeFlavorOptions

FLAVORS = {
    # Upstream Kubernetes
    "kubernetes-1.10": {
        "desc": "Kubernetes 1.10",
        "default_version": "1.9",
    },
    "kubernetes-1.9": {
        "desc": "Kubernetes 1.9",
        "default_version": "1.9",
    },
    "kubernetes-1.8": {
        "desc": "Kubernetes 1.8",
        "default_version": "1.7",
        "config": {
            "kube_config": {
                "use_apps_api": "apps/v1beta2",
                "use_apps_apigroup": "apps",
            }
        }
    },
    "kubernetes-1.7": {
        "desc": "Kubernetes 1.7",
        "default_version": "1.7",
        "config": {
            "kube_config": {
                "use_rbac_api": "rbac.authorization.k8s.io/v1beta1",
                "use_apps_api": "extensions/v1beta1",
                "use_apps_apigroup": "extensions",
            }
        }
    },
    "kubernetes-1.6": {
        "desc": "Kubernetes 1.6",
        "default_version": "1.6",
        "config": {
            "kube_config": {
                "use_rbac_api": "rbac.authorization.k8s.io/v1beta1",
                "use_apps_api": "extensions/v1beta1",
                "use_apps_apigroup": "extensions",
                "use_netpol_annotation": True,
                "use_netpol_apigroup": "extensions",
            },
        }
    },
    # Red Hat OpenShift Container Platform
    "openshift-3.9": {
        "desc": "Red Hat OpenShift Container Platform 3.9",
        "default_version": "1.9",
        "config": {
            "kube_config": {
                "use_external_service_ip_allocator": True,
                "use_privileged_containers": True,
                "use_openshift_security_context_constraints": True,
                "use_cnideploy_initcontainer": True,
                "allow_kube_api_default_epg": True,
                "kubectl": "oc",
                "system_namespace": "aci-containers-system",
            },
            "aci_config": {
                "vmm_domain": {
                    "type": "OpenShift",
                },
            },
        },
    },
    "openshift-3.6": {
        "desc": "Red Hat OpenShift Container Platform 3.6",
        "default_version": "1.6",
        "config": {
            "kube_config": {
                "use_external_service_ip_allocator": True,
                "use_privileged_containers": True,
                "use_openshift_security_context_constraints": True,
                "use_cnideploy_initcontainer": True,
                "allow_kube_api_default_epg": True,
                "use_rbac_api": "v1",
                "use_apps_api": "extensions/v1beta1",
                "use_apps_apigroup": "extensions",
                "use_netpol_apigroup": "extensions",
                "use_netpol_annotation": True,
                "kubectl": "oc",
                "system_namespace": "aci-containers-system",
            },
            "aci_config": {
                "vmm_domain": {
                    "type": "OpenShift",
                },
            },
        },
    },
    # Docker Universal Control Plane (UCP)
    "docker-ucp-3.0": {
        "desc": "Docker Universal Control Plane (UCP) 3.0",
        "default_version": "1.7",
        "config": {
            "kube_config": {
                "use_apps_api": "apps/v1beta2",
                "use_apps_apigroup": "apps",
                "use_cluster_role": False,
                "use_cnideploy_initcontainer": True,
            }
        }
    },
    # CloudFoundry
    "cloudfoundry-1.0": {
        "desc": "CloudFoundry cf-deployment 1.x",
        "default_version": "1.9",
        "config": {
            "aci_config": {
                "vmm_domain": {
                    "type": "CloudFoundry",
                },
            },
        },
        "options": CfFlavorOptions,
    }
}


def info(msg):
    print("INFO: " + msg, file=sys.stderr)


def warn(msg):
    print("WARN: " + msg, file=sys.stderr)


def err(msg):
    print("ERR:  " + msg, file=sys.stderr)


def json_indent(s):
    return json.dumps(s, indent=4, separators=(',', ': '), sort_keys=True)


def yaml_quote(s):
    return "'%s'" % str(s).replace("'", "''")


def yaml_indent(s, **kwargs):
    return yaml.dump(s, **kwargs)


def yaml_list_dict(l):
    out = "\n"
    for d in l:
        keys = sorted(d.keys())
        prefix = "  - "
        for k in keys:
            out += "%s%s: %s\n" % (prefix, k, d[k])
            prefix = "    "
    return out


def list_unicode_strings(l):
    return "['" + "', '".join(l) + "']"


def deep_merge(user, default):
    if isinstance(user, dict) and isinstance(default, dict):
        for k, v in default.items():
            if k not in user:
                user[k] = v
            else:
                user[k] = deep_merge(user[k], v)
    return copy.deepcopy(user)


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
                "type": "Kubernetes",
                "encap_type": "vxlan",
                "mcast_fabric": "225.1.2.3",
                "mcast_range": {
                    "start": "225.20.1.1",
                    "end": "225.20.255.255",
                },
                "nested_inside": {},
            },
            "client_cert": False,
            "client_ssl": True,
            "use_inst_tag": True,
        },
        "net_config": {
            "node_subnet": None,
            "pod_subnet": None,
            "extern_dynamic": None,
            "extern_static": None,
            "node_svc_subnet": None,
            "kubeapi_vlan": None,
            "service_vlan": None,
            "service_monitor_interval": 0,
        },
        "kube_config": {
            "controller": "1.1.1.1",
            "use_rbac_api": "rbac.authorization.k8s.io/v1",
            "use_apps_api": "apps/v1",
            "use_apps_apigroup": "apps",
            "use_netpol_apigroup": "networking.k8s.io",
            "use_netpol_annotation": False,
            "use_cluster_role": True,
            "image_pull_policy": "Always",
            "kubectl": "kubectl",
            "system_namespace": "kube-system",
        },
        "registry": {
            "image_prefix": "noiro",
        },
        "logging": {
            "controller_log_level": "info",
            "hostagent_log_level": "info",
            "opflexagent_log_level": "info",
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

            # This black magic forces pyyaml to load YAML strings as
            # unicode rather than byte strings in Python 2, thus
            # ensuring that the type of strings is consistent across
            # versions.  From
            # https://stackoverflow.com/a/2967461/3857947.
            def construct_yaml_str(self, node):
                return self.construct_scalar(node)
            yaml.Loader.add_constructor(u'tag:yaml.org,2002:str', construct_yaml_str)
            with open(config_file, 'r') as file:
                config = yaml.load(file)
    if config is None:
        config = {}
    return config


def config_discover(config, prov_apic):
    apic = None
    if prov_apic is not None:
        apic = get_apic(config)

    ret = {
        "net_config": {
            "infra_vlan": None,
        }
    }
    if apic is not None:
        infra_vlan = apic.get_infravlan()
        ret["net_config"]["infra_vlan"] = infra_vlan
        orig_infra_vlan = config["net_config"].get("infra_vlan")
        if orig_infra_vlan is not None and orig_infra_vlan != infra_vlan:
            warn("ACI infra_vlan (%s) is different from input file (%s)" %
                 (infra_vlan, orig_infra_vlan))
        if orig_infra_vlan is None:
            info("Using infra_vlan from ACI: %s" %
                 (infra_vlan,))
    return ret


def config_set_dst(pod_cidr):
    rtr, mask = pod_cidr.split('/')
    ip = ipaddress.ip_address(rtr)
    if ip.version == 4:
        return "0.0.0.0/0"
    else:
        return "::/0"


def cidr_split(cidr):
    rtr, mask = cidr.split('/')
    ip = ipaddress.ip_address(rtr)
    if ip.version == 4:
        n = ipaddress.IPv4Network(cidr, strict=False)
    else:
        n = ipaddress.IPv6Network(cidr, strict=False)
    first, last = n[2], n[-2]
    return str(first), str(last), str(n[1]), str(n.network_address), mask


def config_adjust(args, config, prov_apic, no_random):
    system_id = config["aci_config"]["system_id"]
    infra_vlan = config["net_config"]["infra_vlan"]
    node_subnet = config["net_config"]["node_subnet"]
    pod_subnet = config["net_config"]["pod_subnet"]
    extern_dynamic = config["net_config"]["extern_dynamic"]
    extern_static = config["net_config"]["extern_static"]
    node_svc_subnet = config["net_config"]["node_svc_subnet"]
    encap_type = config["aci_config"]["vmm_domain"]["encap_type"]
    system_namespace = config["kube_config"]["system_namespace"]
    tenant = system_id
    token = str(uuid.uuid4())
    if args.version_token:
        token = args.version_token

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
                "vlan_pool": system_id + "-vpool",
                "vlan_range": {
                    "start": None,
                    "end": None,
                }
            },
            "sync_login": {
                "username": system_id,
                "password": generate_password(no_random),
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
                system_namespace: {
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
                            "dst": config_set_dst(pod_subnet),
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
        "cf_config": {
            "default_endpoint_group": {
                "tenant": tenant,
                "app_profile": "cloudfoundry",
                "group": "cf-app-default",
            },
            "node_subnet_cidr": "%s/%s" % cidr_split(node_subnet)[3:],
            "node_epg": "cf-node",
            "app_ip_pool": [
                {
                    "start": cidr_split(pod_subnet)[0],
                    "end": cidr_split(pod_subnet)[1],
                }
            ],
            "app_subnet": "%s/%s" % cidr_split(pod_subnet)[2::2],
            "dynamic_ext_ip_pool": [
                {
                    "start": cidr_split(extern_dynamic)[0],
                    "end": cidr_split(extern_dynamic)[1],
                },
            ],
            "static_ext_ip_pool": [
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
            "api_port": 9900,
            "key_value_port": 9902,
        },
        "registry": {
            "configuration_version": token,
        }
    }
    if config["net_config"].get("vip_subnet"):
        vip_subnet = cidr_split(config["net_config"]["vip_subnet"])
        adj_config["cf_config"]["app_vip_pool"] = [
            {
                "start": vip_subnet[0],
                "end": vip_subnet[1],
            }
        ]
        adj_config["cf_config"]["app_vip_subnet"] = [
            "%s/%s" % vip_subnet[2::2]]

    adj_config["cf_config"]["node_network"] = (
        "%s|%s|%s" % (
            tenant,
            adj_config['cf_config']['default_endpoint_group']['app_profile'],
            adj_config['cf_config']['node_epg']))

    return adj_config


def config_validate(flavor_opts, config):
    def Raise(exception):
        raise exception

    required = lambda x: True if x else Raise(Exception("Missing option"))
    lower_in = lambda y: (
        lambda x: (
            (True if str(x).lower() in y
             else Raise(Exception("Invalid value: %s; "
                                  "Expected one of: {%s}" %
                                  (x, ','.join(y)))))))
    isname = lambda x, l: (1 < len(x) < l) and \
        x[0].isalpha() and x.replace('_', '').isalnum() \
        if x else Raise(Exception("Invalid name"))
    get = lambda t: functools.reduce(lambda x, y: x and x.get(y), t, config)

    checks = {
        # ACI config
        "aci_config/system_id": (get(("aci_config", "system_id")),
                                 lambda x: required(x) and isname(x, 32)),
        "aci_config/apic_host": (get(("aci_config", "apic_hosts")), required),
        "aci_config/aep": (get(("aci_config", "aep")), required),
        "aci_config/vrf/name": (get(("aci_config", "vrf", "name")), required),
        "aci_config/vrf/tenant": (get(("aci_config", "vrf", "tenant")),
                                  required),
        "aci_config/l3out/name": (get(("aci_config", "l3out", "name")),
                                  required),
        "aci_config/l3out/external-networks":
        (get(("aci_config", "l3out", "external_networks")), required),

        # Network Config
        "net_config/infra_vlan": (get(("net_config", "infra_vlan")),
                                  required),
        "net_config/service_vlan": (get(("net_config", "service_vlan")),
                                    required),
        "net_config/node_subnet": (get(("net_config", "node_subnet")),
                                   required),
        "net_config/pod_subnet": (get(("net_config", "pod_subnet")),
                                  required),
        "net_config/extern_dynamic": (get(("net_config", "extern_dynamic")),
                                      required),
        "net_config/extern_static": (get(("net_config", "extern_static")),
                                     required),
        "net_config/node_svc_subnet": (get(("net_config", "node_svc_subnet")),
                                       required),
    }

    if flavor_opts.get("apic", {}).get("use_kubeapi_vlan", True):
        checks["net_config/kubeapi_vlan"] = (
            get(("net_config", "kubeapi_vlan")), required)

    # Versions
    for field in flavor_opts.get('version_fields', VERSION_FIELDS):
        checks[field] = (get(("registry", field)), required)

    if flavor_opts.get("apic", {}).get("associate_aep_to_nested_inside_domain",
                                       False):
        checks["aci_config/vmm_domain/nested_inside/type"] = (
            get(("aci_config", "vmm_domain", "nested_inside", "type")),
            required)

    if get(("aci_config", "vmm_domain", "encap_type")) == "vlan":
        checks["aci_config/vmm_domain/vlan_range/start"] = \
            (get(("aci_config", "vmm_domain", "vlan_range", "start")),
             required)
        checks["aci_config/vmm_domain/vlan_range/end"] = \
            (get(("aci_config", "vmm_domain", "vlan_range", "end")),
             required)

    if get(("aci_config", "vmm_domain", "nested_inside", "type")):
        checks["aci_config/vmm_domain/nested_inside/type"] = \
            (get(("aci_config", "vmm_domain", "nested_inside", "type")),
             lower_in({"vmware"}))
        checks["aci_config/vmm_domain/nested_inside/name"] = \
            (get(("aci_config", "vmm_domain", "nested_inside", "name")),
             required)

    if get(("provision", "prov_apic")) is not None:
        checks.update({
            # auth for API access
            "aci_config/apic_login/username":
            (get(("aci_config", "apic_login", "username")), required),
            "aci_config/apic_login/password":
            (get(("aci_config", "apic_login", "password")), required),
        })

    if flavor_opts.get('vip_pool_required', False):
        checks["net_config/vip_subnet"] = (
            get(("net_config", "vip_subnet")), required)

    iso_seg_check = (
        lambda x: True
        if all(('name' in iso and 'subnet' in iso) for iso in x)
        else Raise(
            Exception("'name' and 'subnet' required for "
                      "each isolation segment")))
    iso_seg = get(("aci_config", "isolation_segments"))
    if iso_seg:
        checks["aci_config/isolation_segments"] = (iso_seg, iso_seg_check)

    ret = True
    for k in sorted(checks.keys()):
        value, validator = checks[k]
        try:
            if not validator(value):
                raise Exception(k)
        except Exception as e:
            err("Invalid configuration for %s: %s" % (k, e))
            ret = False
    return ret


def config_validate_preexisting(config, prov_apic):
    try:
        if prov_apic is not None:
            apic = get_apic(config)
            if apic is None:
                return False

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
        warn("Unable to validate resources on APIC: '%s'" % e.message)
    return True


def generate_sample(filep):
    data = pkgutil.get_data('acc_provision', 'templates/provision-config.yaml')
    filep.write(data)
    filep.flush()
    return filep


def generate_password(no_random):
    chars = string.ascii_letters + string.digits + ("_-+=!" * 3)
    ret = ''.join(random.SystemRandom().sample(chars, 20))
    if no_random:
        ret = "NotRandom!"
    return ret


def generate_cert(username, cert_file, key_file):
    if not exists(cert_file) or not exists(key_file):
        info("Generating certs for kubernetes controller")
        info("  Private key file: \"%s\"" % key_file)
        info("  Certificate file: \"%s\"" % cert_file)

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().O = "Cisco Systems"
        cert.get_subject().CN = "User %s" % username
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(-12 * 60 * 60)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        # Work around this bug:
        # https://github.com/pyca/pyopenssl/issues/741

        # This should be b'sha1' on both 2 and 3, but the bug requires
        # passing a string on Python 3.
        if sys.version_info[0] >= 3:
            hash_algorithm = 'sha1'
        else:
            hash_algorithm = b'sha1'
        cert.sign(k, hash_algorithm)

        cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
        with open(cert_file, "wb") as certp:
            certp.write(cert_data)
        with open(key_file, "wb") as keyp:
            keyp.write(key_data)
    else:
        # Do not overwrite previously generated data if it exists
        info("Reusing existing certs for kubernetes controller")
        info("  Private key file: \"%s\"" % key_file)
        info("  Certificate file: \"%s\"" % cert_file)
        with open(cert_file, "rb") as certp:
            cert_data = certp.read()
        with open(key_file, "rb") as keyp:
            key_data = keyp.read()
    return key_data, cert_data


def get_jinja_template(file):
    env = Environment(
        loader=PackageLoader('acc_provision', 'templates'),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True
    )
    env.filters['base64enc'] = lambda s: base64.b64encode(s).decode("ascii")
    env.filters['cf_secret'] = lambda s: yaml.safe_dump(s.decode("ascii"), default_style='|')
    env.filters['json'] = json_indent
    env.filters['yaml'] = yaml_indent
    env.filters['yaml_quote'] = yaml_quote
    env.filters['yaml_list_dict'] = yaml_list_dict
    env.filters['list_unicode_strings'] = list_unicode_strings
    template = env.get_template(file)
    return template


def generate_kube_yaml(config, output):
    template = get_jinja_template('aci-containers.yaml')

    kube_objects = [
        "configmap", "secret", "serviceaccount",
        "daemonset", "deployment",
    ]
    if config["kube_config"].get("use_openshift_security_context_constraints",
                                 False):
        kube_objects.append("securitycontextconstraints")
    if config["kube_config"].get("use_cluster_role", False):
        kube_objects.extend(["clusterrolebinding", "clusterrole"])

    if output and output != "/dev/null":
        outname = output
        applyname = output
        if output == "-":
            outname = "<stdout>"
            applyname = "<filename>"
            output = sys.stdout
        else:
            applyname = os.path.basename(output)

        info("Using configuration label aci-containers-config-version=" +
             str(config["registry"]["configuration_version"]))
        info("Writing kubernetes infrastructure YAML to %s" % outname)
        template.stream(config=config).dump(output)
        info("Apply infrastructure YAML using:")
        info("  %s apply -f %s" %
             (config["kube_config"]["kubectl"], applyname))
        info("  %s -n %s delete %s -l "
             " 'aci-containers-config-version,"
             "aci-containers-config-version notin (%s)'" %
             (config["kube_config"]["kubectl"],
              config["kube_config"]["system_namespace"],
              ",".join(kube_objects),
              str(config["registry"]["configuration_version"])))
    return config


def generate_cf_yaml(config, output):
    template = get_jinja_template('aci-cf-containers.yaml')

    if output and output != "/dev/null":
        outname = output
        applyname = output
        if output == "-":
            outname = "<stdout>"
            applyname = "<filename>"
            output = sys.stdout
        else:
            applyname = os.path.basename(output)

        info("Writing deployment vars for ACI add-ons to %s" % outname)
        template.stream(config=config).dump(output)
        pg = ("%s/%s" %
              (config['aci_config']['vmm_domain']['nested_inside']['name'],
               config['cf_config']['node_network']))
        node_subnet = config["net_config"]["node_subnet"]
        node_subnet_cidr = "%s/%s" % cidr_split(node_subnet)[3:]
        node_subnet_gw = cidr_split(node_subnet)[2]
        info("Steps to deploy ACI add-ons:")
        # TODO Merge steps 1 & 2 into a single cloud-config update
        info("1. Manually update your cloud config to use vCenter Portgroup " +
             "'" + pg + "' in 'cloud_properties' of subnet " +
             node_subnet_cidr + " in the network named " +
             "'default'. E.g." + '''

networks:
- name: default
  type: manual
  subnets:
  - range: %s
    gateway: %s
    [...]
    cloud_properties:
      name: %s
''' % (node_subnet_cidr, node_subnet_gw, pg))
        info("2. Update cloud config using:")
        info("  bosh update-cloud-config <your current cloud config file> " +
             "-o <aci-containers-release>/manifest-generation/" +
             "cloud_config_ops.yml -l %s" % applyname)
        info("3. Deploy ACI add-ons using:")
        info("  bosh deploy <your current arguments> -o " +
             "<aci-containers-release>/manifest-generation/" +
             "cf_ops.yml -l %s" % applyname)

    return config


CfFlavorOptions['template_generator'] = generate_cf_yaml


def generate_apic_config(flavor_opts, config, prov_apic, apic_file):
    configurator = ApicKubeConfig(config)
    for k, v in flavor_opts.get("apic", {}).items():
        setattr(configurator, k, v)
    apic_config = configurator.get_config()
    if apic_file:
        if apic_file == "-":
            info("Writing apic configuration to \"STDOUT\"")
            ApicKubeConfig.save_config(apic_config, sys.stdout)
        else:
            info("Writing apic configuration to \"%s\"" % apic_file)
            with open(apic_file, 'w') as outfile:
                ApicKubeConfig.save_config(apic_config, outfile)

    ret = True
    sync_login = config["aci_config"]["sync_login"]["username"]
    if prov_apic is not None:
        apic = get_apic(config)
        if apic is not None:
            if prov_apic is True:
                info("Provisioning configuration in APIC")
                apic.provision(apic_config, sync_login)
            if prov_apic is False:
                info("Unprovisioning configuration in APIC")
                system_id = config["aci_config"]["system_id"]
                tenant = config["aci_config"]["vrf"]["tenant"]
                vrf_tenant = config["aci_config"]["vrf"]["tenant"]
                apic.unprovision(apic_config, system_id, tenant, vrf_tenant)
            ret = False if apic.errors > 0 else True
    return ret


def get_apic(config):
    apic_host = config["aci_config"]["apic_hosts"][0]
    apic_username = config["aci_config"]["apic_login"]["username"]
    apic_password = config["aci_config"]["apic_login"]["password"]
    timeout = config["aci_config"]["apic_login"]["timeout"]
    debug = config["provision"]["debug_apic"]
    apic = Apic(
        apic_host, apic_username, apic_password,
        timeout=timeout, debug=debug)
    if apic.cookies is None:
        return None
    return apic


class CustomFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        ret = super(CustomFormatter, self)._format_action_invocation(action)
        ret = ret.replace(' ,', ',')
        ret = ret.replace(' file,', ',')
        ret = ret.replace(' name,', ',')
        ret = ret.replace(' pass,', ',')
        return ret


def parse_args():
    version = 'Unknown'
    try:
        version = pkg_resources.require("acc_provision")[0].version
    except pkg_resources.DistributionNotFound:
        # ignore, expected in case running from source
        pass

    parser = argparse.ArgumentParser(
        description='Provision an ACI/Kubernetes installation',
        formatter_class=CustomFormatter,
    )
    parser.add_argument(
        '-v', '--version', action='version', version=version)
    parser.add_argument(
        '--debug', action='store_true', default=False,
        help='enable debug')
    parser.add_argument(
        '--sample', action='store_true', default=False,
        help='print a sample input file with fabric configuration')
    parser.add_argument(
        '-c', '--config', default="-", metavar='file',
        help='input file with your fabric configuration')
    parser.add_argument(
        '-o', '--output', default="-", metavar='file',
        help='output file for your kubernetes deployment')
    parser.add_argument(
        '-a', '--apic', action='store_true', default=False,
        help='create/validate the required APIC resources')
    parser.add_argument(
        '-d', '--delete', action='store_true', default=False,
        help='delete the APIC resources that would have been created')
    parser.add_argument(
        '-u', '--username', default=None, metavar='name',
        help='apic-admin username to use for APIC API access')
    parser.add_argument(
        '-p', '--password', default=None, metavar='pass',
        help='apic-admin password to use for APIC API access')
    parser.add_argument(
        '-w', '--timeout', default=None, metavar='timeout',
        help='wait/timeout to use for APIC API access')
    parser.add_argument(
        '--list-flavors', action='store_true', default=False,
        help='list available configuration flavors')
    parser.add_argument(
        '-f', '--flavor', default=None, metavar='flavor',
        help='set configuration flavor.  Example: openshift-3.6')
    parser.add_argument(
        '-t', '--version-token', default=None, metavar='token',
        help='set a configuration version token.  Default is UUID.')
    return parser.parse_args()


def provision(args, apic_file, no_random):
    config_file = args.config
    output_file = args.output

    prov_apic = None
    if args.apic:
        prov_apic = True
    if args.delete:
        prov_apic = False

    timeout = None
    if args.timeout:
        try:
            if int(args.timeout) >= 0:
                timeout = args.timeout
        except ValueError:
            # ignore that timeout value
            warn("Invalid timeout value ignored: '%s'" % timeout)

    generate_cert_data = True
    if args.delete:
        output_file = "/dev/null"
        generate_cert_data = False

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
            "debug_apic": args.debug,
        },
    }
    if args.username:
        config["aci_config"]["apic_login"]["username"] = args.username

    config["aci_config"]["apic_login"]["password"] = \
        args.password if args.password else os.environ.get('ACC_PROVISION_PASS')
    config["aci_config"]["apic_login"]["timeout"] = timeout

    # Create config
    user_config = config_user(config_file)
    deep_merge(config, user_config)

    flavor = DEFAULT_FLAVOR
    if args.flavor:
        flavor = args.flavor
    if flavor in FLAVORS:
        info("Using configuration flavor " + flavor)
        if "config" in FLAVORS[flavor]:
            deep_merge(config, FLAVORS[flavor]["config"])
        if "default_version" in FLAVORS[flavor]:
            deep_merge(config, {
                "registry": {
                    "version": FLAVORS[flavor]["default_version"]
                }
            })
    else:
        err("Unknown flavor %s" % flavor)
        return False
    flavor_opts = FLAVORS[flavor].get("options", DEFAULT_FLAVOR_OPTIONS)

    deep_merge(config, config_default())

    if config["registry"]["version"] in VERSIONS:
        deep_merge(config,
                   {"registry": VERSIONS[config["registry"]["version"]]})

    deep_merge(config, config_discover(config, prov_apic))

    # Validate APIC access
    if prov_apic is not None:
        apic = get_apic(config)
        if apic is None:
            err("Not able to login to the APIC, please check username or password")
            return False

    # Validate config
    if not config_validate(flavor_opts, config):
        err("Please fix configuration and retry.")
        return False

    # Adjust config based on convention/apic data
    adj_config = config_adjust(args, config, prov_apic, no_random)
    deep_merge(config, adj_config)

    # Advisory checks, including apic checks, ignore failures
    if not config_validate_preexisting(config, prov_apic):
        # Ignore failures, this check is just advisory for now
        pass

    # generate key and cert if needed
    username = config["aci_config"]["sync_login"]["username"]
    certfile = config["aci_config"]["sync_login"]["certfile"]
    keyfile = config["aci_config"]["sync_login"]["keyfile"]
    key_data, cert_data = None, None
    if generate_cert_data:
        key_data, cert_data = generate_cert(username, certfile, keyfile)
    config["aci_config"]["sync_login"]["key_data"] = key_data
    config["aci_config"]["sync_login"]["cert_data"] = cert_data

    # generate output files; and program apic if needed
    ret = generate_apic_config(flavor_opts, config, prov_apic, apic_file)
    gen = flavor_opts.get("template_generator", generate_kube_yaml)
    gen(config, output_file)
    return ret


def main(args=None, apic_file=None, no_random=False):
    # apic_file and no_random are used by the test functions
    if args is None:
        args = parse_args()

    if args.list_flavors:
        info("Available configuration flavors:")
        for flavor in FLAVORS:
            info(flavor + ":\t" + FLAVORS[flavor]["desc"])
        return
    if args.flavor is not None and args.flavor not in FLAVORS:
        err("Invalid configuration flavor: " + args.flavor)
        sys.exit(1)

    success = True
    if args.debug:
        success = provision(args, apic_file, no_random)
    else:
        try:
            success = provision(args, apic_file, no_random)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            success = False
            err("%s: %s" % (e.__class__.__name__, e))

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
