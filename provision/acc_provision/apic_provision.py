from __future__ import print_function

import json
import sys

import requests

requests.packages.urllib3.disable_warnings()


def err(msg):
    print("ERR:  " + msg, file=sys.stderr)


def warn(msg):
    print("WARN: " + msg, file=sys.stderr)


def dbg(msg):
    print("DBG:  " + msg, file=sys.stderr)


class Apic(object):
    def __init__(self, addr, username, password,
                 ssl=True, verify=False, debug=False):
        self.addr = addr
        self.ssl = ssl
        self.username = username
        self.password = password
        self.cookies = None
        self.verify = verify
        self.debug = debug
        self.login()

    def url(self, path):
        if self.ssl:
            return 'https://%s%s' % (self.addr, path)
        return 'http://%s%s' % (self.addr, path)

    def get(self, path, data=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        return requests.get(self.url(path), **args)

    def post(self, path, data):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        return requests.post(self.url(path), **args)

    def delete(self, path, data=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        return requests.delete(self.url(path), **args)

    def login(self):
        data = '{"aaaUser":{"attributes":{"name": "%s", "pwd": "%s"}}}' % \
            (self.username, self.password)
        path = '/api/aaaLogin.json'
        req = requests.post(self.url(path), data=data, verify=False)
        if req.status_code == 200:
            resp = json.loads(req.text)
            token = resp["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self.cookies = {'APIC-Cookie': token}
        return req

    def check_resp(self, resp):
        respj = json.loads(resp.text)
        if len(respj["imdata"]) > 0:
            ret = respj["imdata"][0]
            if "error" in ret:
                raise Exception("APIC REST Error: %s" % ret["error"])
        return resp

    def get_path(self, path):
        ret = None
        try:
            resp = self.get(path)
            self.check_resp(resp)
            respj = json.loads(resp.text)
            if len(respj["imdata"]) > 0:
                ret = respj["imdata"][0]
        except Exception as e:
            err("Error in getting %s: %s: " % (path, str(e)))
        return ret

    def get_infravlan(self):
        infra_vlan = None
        path = '/api/node/mo/uni/infra/attentp-default/provacc' + \
               '/rsfuncToEpg-[uni/tn-infra/ap-access/epg-default].json'
        data = self.get_path(path)
        if data:
            encap = data["infraRsFuncToEpg"]["attributes"]["encap"]
            infra_vlan = int(encap.split("-")[1])
        return infra_vlan

    def get_aep(self, aep_name):
        path = '/api/mo/uni/infra/attentp-%s.json' % aep_name
        return self.get_path(path)

    def get_vrf(self, tenant, name):
        path = '/api/mo/uni/tn-%s/ctx-%s.json' % (tenant, name)
        return self.get_path(path)

    def get_l3out(self, tenant, name):
        path = '/api/mo/uni/tn-%s/out-%s.json' % (tenant, name)
        return self.get_path(path)

    def get_user(self, name):
        path = "/api/node/mo/uni/userext/user-%s.json" % name
        return self.get_path(path)

    def provision(self, data, sync_login):
        ignore_list = []
        if self.get_user(sync_login):
            warn("User already exists (%s), skipping user provisioning" %
                 sync_login)
            ignore_list.append("/api/node/mo/uni/userext/user-%s.json" %
                               sync_login)

        for path, config in data:
            try:
                if path in ignore_list:
                    continue
                if config is not None:
                    resp = self.post(path, config)
                    self.check_resp(resp)
                    if self.debug:
                        dbg("%s: %s" % (path, resp.text))
            except Exception as e:
                # log it, otherwise ignore it
                err("Error in provisioning %s: %s" % (path, str(e)))

    def unprovision(self, data):
        for path, config in data:
            try:
                if path not in [
                        "/api/mo/uni/infra.json",
                        "/api/mo/uni/tn-common.json",
                ]:
                    resp = self.delete(path)
                    self.check_resp(resp)
                    if self.debug:
                        dbg("%s: %s" % (path, resp.text))
            except Exception as e:
                # log it, otherwise ignore it
                err("Error in un-provisioning %s: %s" % (path, str(e)))


class ApicKubeConfig(object):
    def __init__(self, config):
        self.config = config

    @staticmethod
    def save_config(config, outfilep):
        for path, data in config:
            print(path, file=outfilep)
            print(data, file=outfilep)

    def get_config(self):
        def update(data, x):
            if x:
                data.append(
                    (x[0], json.dumps(x[1], sort_keys=True, indent=4)))
                for path in x[2:]:
                    data.append((path, None))

        data = []
        update(data, self.vlan_pool())
        update(data, self.mcast_pool())
        update(data, self.phys_dom())
        update(data, self.kube_dom())
        update(data, self.associate_aep())
        update(data, self.opflex_cert())
        update(data, self.common_tn())
        update(data, self.kube_tn())
        update(data, self.kube_user())
        update(data, self.kube_cert())
        return data

    def vlan_pool(self):
        pool_name = self.config["aci_config"]["physical_domain"]["vlan_pool"]
        kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
        service_vlan = self.config["net_config"]["service_vlan"]

        path = "/api/mo/uni/infra/vlanns-[%s]-static.json" % pool_name
        data = {
            "fvnsVlanInstP": {
                "attributes": {
                    "name": pool_name,
                    "allocMode": "static"
                },
                "children": [
                    {
                        "fvnsEncapBlk": {
                            "attributes": {
                                "allocMode": "static",
                                "from": "vlan-%s" % kubeapi_vlan,
                                "to": "vlan-%s" % kubeapi_vlan
                            }
                        }
                    },
                    {
                        "fvnsEncapBlk": {
                            "attributes": {
                                "allocMode": "static",
                                "from": "vlan-%s" % service_vlan,
                                "to": "vlan-%s" % service_vlan
                            }
                        }
                    }
                ]
            }
        }
        return path, data

    def mcast_pool(self):
        mpool_name = self.config["aci_config"]["vmm_domain"]["mcast_pool"]
        mcast_start = self.config["aci_config"]["vmm_domain"]["mcast_range"]["start"]
        mcast_end = self.config["aci_config"]["vmm_domain"]["mcast_range"]["end"]

        path = "/api/mo/uni/infra/maddrns-%s.json" % mpool_name
        data = {
            "fvnsMcastAddrInstP": {
                "attributes": {
                    "name": mpool_name,
                    "dn": "uni/infra/maddrns-%s" % mpool_name
                },
                "children": [
                    {
                        "fvnsMcastAddrBlk": {
                            "attributes": {
                                "from": mcast_start,
                                "to": mcast_end
                            }
                        }
                    }
                ]
            }
        }
        return path, data

    def phys_dom(self):
        phys_name = self.config["aci_config"]["physical_domain"]["domain"]
        pool_name = self.config["aci_config"]["physical_domain"]["vlan_pool"]

        path = "/api/mo/uni/phys-%s.json" % phys_name
        data = {
            "physDomP": {
                "attributes": {
                    "dn": "uni/phys-%s" % phys_name,
                    "name": phys_name
                },
                "children": [
                    {
                        "infraRsVlanNs": {
                            "attributes": {
                                "tDn": "uni/infra/vlanns-[%s]-static" % pool_name
                            },
                        }
                    }
                ]
            }
        }
        return path, data

    def kube_dom(self):
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        encap_type = self.config["aci_config"]["vmm_domain"]["encap_type"]
        mcast_fabric = self.config["aci_config"]["vmm_domain"]["mcast_fabric"]
        mpool_name = self.config["aci_config"]["vmm_domain"]["mcast_pool"]
        kube_controller = self.config["kube_config"]["controller"]

        path = "/api/mo/uni/vmmp-Kubernetes/dom-%s.json" % vmm_name
        data = {
            "vmmDomP": {
                "attributes": {
                    "name": vmm_name,
                    "mode": "k8s",
                    "enfPref": "sw",
                    "encapMode": encap_type,
                    "prefEncapMode": encap_type,
                    "mcastAddr": mcast_fabric,
                },
                "children": [
                    {
                        "vmmCtrlrP": {
                            "attributes": {
                                "name": vmm_name,
                                "mode": "k8s",
                                "scope": "kubernetes",
                                "hostOrIp": kube_controller,
                            },
                        }
                    },
                    {
                        "vmmRsDomMcastAddrNs": {
                            "attributes": {
                                "tDn": "uni/infra/maddrns-%s" % mpool_name
                            }
                        }
                    }
                ]
            }
        }
        return path, data

    def associate_aep(self):
        aep_name = self.config["aci_config"]["aep"]
        phys_name = self.config["aci_config"]["physical_domain"]["domain"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        infra_vlan = self.config["net_config"]["infra_vlan"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]

        path = "/api/mo/uni/infra.json"
        data = {
            "infraAttEntityP": {
                "attributes": {
                    "name": aep_name,
                },
                "children": [
                    {
                        "infraRsDomP": {
                            "attributes": {
                                "tDn": "uni/vmmp-Kubernetes/dom-%s" % vmm_name
                            }
                        }
                    },
                    {
                        "infraRsDomP": {
                            "attributes": {
                                "tDn": "uni/phys-%s" % phys_name
                            }
                        }
                    },
                    {
                        "infraProvAcc": {
                            "attributes": {
                                "name": "provacc",
                            },
                            "children": [
                                {
                                    "infraRsFuncToEpg": {
                                        "attributes": {
                                            "encap": "vlan-%s" % str(infra_vlan),
                                            "mode": "regular",
                                            "tDn": "uni/tn-infra/ap-access/epg-default"
                                        }
                                    }
                                },
                                {
                                    "dhcpInfraProvP": {
                                        "attributes": {
                                            "mode": "controller",
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "infraGeneric": {
                            "attributes": {
                                "name": "default",
                            },
                            "children": [
                                {
                                    "infraRsFuncToEpg": {
                                        "attributes": {
                                            "tDn": "uni/tn-%s/ap-kubernetes/epg-kube-nodes" % (tn_name,),
                                            "encap": "vlan-%s" % (kubeapi_vlan,),
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }

        base = '/api/mo/uni/infra/attentp-%s' % aep_name
        rsvmm = base + '/rsdomP-[uni/vmmp-Kubernetes/dom-%s].json' % vmm_name
        rsphy = base + '/rsdomP-[uni/phys-%s].json' % phys_name
        rsfun = base + '/gen-default.json'
        return path, data, rsvmm, rsphy, rsfun

    def opflex_cert(self):
        def yesno(flag):
            if flag:
                return "yes"
            return "no"

        client_cert = self.config["aci_config"]["client_cert"]
        client_ssl = self.config["aci_config"]["client_ssl"]

        path = "/api/mo/uni/infra.json"
        data = {
            "infraSetPol": {
                "attributes": {
                    "opflexpAuthenticateClients": yesno(client_cert),
                    "opflexpUseSsl": yesno(client_ssl),
                },
            },
        }
        return path, data

    def common_tn(self):
        system_id = self.config["aci_config"]["system_id"]

        path = "/api/mo/uni/tn-common.json"
        data = {
            "fvTenant": {
                "attributes": {
                    "name": "common",
                    "dn": "uni/tn-common",
                },
                "children": [
                    {
                        "vzFilter": {
                            "attributes": {
                                "name": "allow-all-filter"
                            },
                            "children": [
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "allow-all"
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzBrCP": {
                            "attributes": {
                                "name": "%s-l3out-allow-all" % system_id
                            },
                            "children": [
                                {
                                    "vzSubj": {
                                        "attributes": {
                                            "name": "allow-all-subj",
                                            "consMatchT": "AtleastOne",
                                            "provMatchT": "AtleastOne"
                                        },
                                        "children": [
                                            {
                                                "vzRsSubjFiltAtt": {
                                                    "attributes": {
                                                        "tnVzFilterName": "allow-all-filter"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    },
                ]
            }
        }

        brc = '/api/mo/uni/tn-common/brc-%s-l3out-allow-all.json' % system_id
        return path, data, brc

    def kube_user(self):
        name = self.config["aci_config"]["sync_login"]["username"]
        password = self.config["aci_config"]["sync_login"]["password"]

        path = "/api/node/mo/uni/userext/user-%s.json" % name
        data = {
            "aaaUser": {
                "attributes": {
                    "name": name,
                    "accountStatus": "active",
                },
                "children": [
                    {
                        "aaaUserDomain": {
                            "attributes": {
                                "name": "all",
                            },
                            "children": [
                                {
                                    "aaaUserRole": {
                                        "attributes": {
                                            "name": "admin",
                                            "privType": "writePriv",
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }

        if password is not None:
            data["aaaUser"]["attributes"]["pwd"] = password
        return path, data

    def kube_cert(self):
        name = self.config["aci_config"]["sync_login"]["username"]
        certfile = self.config["aci_config"]["sync_login"]["certfile"]

        if certfile is None:
            return None

        cert = None
        with open(certfile, "r") as cfile:
            cert = cfile.read()
        path = "/api/node/mo/uni/userext/user-%s.json" % name
        data = {
            "aaaUser": {
                "attributes": {
                    "name": name,
                },
                "children": [
                    {
                        "aaaUserCert": {
                            "attributes": {
                                "name": "%s.crt" % name,
                                "data": cert,
                            }
                        }
                    }
                ]
            }
        }
        return path, data

    def kube_tn(self):
        system_id = self.config["aci_config"]["system_id"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        phys_name = self.config["aci_config"]["physical_domain"]["domain"]
        kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
        kube_vrf = self.config["aci_config"]["vrf"]["name"]
        kube_l3out = self.config["aci_config"]["l3out"]["name"]
        node_subnet = self.config["net_config"]["node_subnet"]
        pod_subnet = self.config["net_config"]["pod_subnet"]

        path = "/api/mo/uni/tn-%s.json" % tn_name
        data = {
            "fvTenant": {
                "attributes": {
                    "name": tn_name,
                    "dn": "uni/tn-%s" % tn_name
                },
                "children": [
                    {
                        "fvAp": {
                            "attributes": {
                                "name": "kubernetes"
                            },
                            "children": [
                                {
                                    "fvAEPg": {
                                        "attributes": {
                                            "name": "kube-default"
                                        },
                                        "children": [
                                            {
                                                "fvRsDomAtt": {
                                                    "attributes": {
                                                        "tDn": "uni/vmmp-Kubernetes/dom-%s" % vmm_name
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsCons": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "dns"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsCons": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "%s-l3out-allow-all" % system_id
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsCons": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "arp"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsCons": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "icmp"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsBd": {
                                                    "attributes": {
                                                        "tnFvBDName": "kube-pod-bd"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                },
                                {
                                    "fvAEPg": {
                                        "attributes": {
                                            "name": "kube-system"
                                        },
                                        "children": [
                                            {
                                                "fvRsProv": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "arp"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsProv": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "dns"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsProv": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "icmp"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsProv": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "health-check"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsCons": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "icmp"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsCons": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "kube-api"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsCons": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "%s-l3out-allow-all" % system_id
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsDomAtt": {
                                                    "attributes": {
                                                        "tDn": "uni/vmmp-Kubernetes/dom-%s" % vmm_name
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsBd": {
                                                    "attributes": {
                                                        "tnFvBDName": "kube-pod-bd"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                },
                                {
                                    "fvAEPg": {
                                        "attributes": {
                                            "name": "kube-nodes"
                                        },
                                        "children": [
                                            {
                                                "fvRsProv": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "kube-api"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsProv": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "icmp"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsCons": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "health-check"
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsCons": {
                                                    "attributes": {
                                                        "tnVzBrCPName": "%s-l3out-allow-all" % system_id
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsDomAtt": {
                                                    "attributes": {
                                                        "encap": "vlan-%s" % kubeapi_vlan,
                                                        "tDn": "uni/phys-%s" % phys_name
                                                    }
                                                }
                                            },
                                            {
                                                "fvRsBd": {
                                                    "attributes": {
                                                        "tnFvBDName": "kube-node-bd"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                },
                            ]
                        }
                    },
                    {
                        "fvBD": {
                            "attributes": {
                                "name": "kube-node-bd"
                            },
                            "children": [
                                {
                                    "fvSubnet": {
                                        "attributes": {
                                            "ip": node_subnet,
                                            "scope": "public"
                                        }
                                    }
                                },
                                {
                                    "fvRsCtx": {
                                        "attributes": {
                                            "tnFvCtxName": kube_vrf
                                        }
                                    }
                                },
                                {
                                    "fvRsBDToOut": {
                                        "attributes": {
                                            "tnL3extOutName": kube_l3out
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "fvBD": {
                            "attributes": {
                                "name": "kube-pod-bd"
                            },
                            "children": [
                                {
                                    "fvSubnet": {
                                        "attributes": {
                                            "ip": pod_subnet
                                        }
                                    }
                                },
                                {
                                    "fvRsCtx": {
                                        "attributes": {
                                            "tnFvCtxName": kube_vrf
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzFilter": {
                            "attributes": {
                                "name": "arp-filter"
                            },
                            "children": [
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "arp",
                                            "etherT": "arp"
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzFilter": {
                            "attributes": {
                                "name": "icmp-filter"
                            },
                            "children": [
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "icmp",
                                            "etherT": "ip",
                                            "prot": "icmp"
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzFilter": {
                            "attributes": {
                                "name": "health-check-filter"
                            },
                            "children": [
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "health-check",
                                            "etherT": "ip",
                                            "prot": "tcp",
                                            "dFromPort": "8000",
                                            "dToPort": "11000",
                                            "stateful": "no",
                                            "tcpRules": ""
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzFilter": {
                            "attributes": {
                                "name": "dns-filter"
                            },
                            "children": [
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "dns-udp",
                                            "etherT": "ip",
                                            "prot": "udp",
                                            "dFromPort": "dns",
                                            "dToPort": "dns"
                                        }
                                    }
                                },
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "dns-tcp",
                                            "etherT": "ip",
                                            "prot": "tcp",
                                            "dFromPort": "dns",
                                            "dToPort": "dns",
                                            "stateful": "no",
                                            "tcpRules": ""
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzFilter": {
                            "attributes": {
                                "name": "kube-api-filter"
                            },
                            "children": [
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "kube-api",
                                            "etherT": "ip",
                                            "prot": "tcp",
                                            "dFromPort": "6443",
                                            "dToPort": "6443",
                                            "stateful": "no",
                                            "tcpRules": ""
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzBrCP": {
                            "attributes": {
                                "name": "arp"
                            },
                            "children": [
                                {
                                    "vzSubj": {
                                        "attributes": {
                                            "name": "arp-subj",
                                            "consMatchT": "AtleastOne",
                                            "provMatchT": "AtleastOne"
                                        },
                                        "children": [
                                            {
                                                "vzRsSubjFiltAtt": {
                                                    "attributes": {
                                                        "tnVzFilterName": "arp-filter"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzBrCP": {
                            "attributes": {
                                "name": "kube-api"
                            },
                            "children": [
                                {
                                    "vzSubj": {
                                        "attributes": {
                                            "name": "kube-api-subj",
                                            "consMatchT": "AtleastOne",
                                            "provMatchT": "AtleastOne"
                                        },
                                        "children": [
                                            {
                                                "vzRsSubjFiltAtt": {
                                                    "attributes": {
                                                        "tnVzFilterName": "kube-api-filter"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzBrCP": {
                            "attributes": {
                                "name": "health-check"
                            },
                            "children": [
                                {
                                    "vzSubj": {
                                        "attributes": {
                                            "name": "health-check-subj",
                                            "consMatchT": "AtleastOne",
                                            "provMatchT": "AtleastOne"
                                        },
                                        "children": [
                                            {
                                                "vzRsSubjFiltAtt": {
                                                    "attributes": {
                                                        "tnVzFilterName": "health-check-filter"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzBrCP": {
                            "attributes": {
                                "name": "dns"
                            },
                            "children": [
                                {
                                    "vzSubj": {
                                        "attributes": {
                                            "name": "dns-subj",
                                            "consMatchT": "AtleastOne",
                                            "provMatchT": "AtleastOne"
                                        },
                                        "children": [
                                            {
                                                "vzRsSubjFiltAtt": {
                                                    "attributes": {
                                                        "tnVzFilterName": "dns-filter"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "vzBrCP": {
                            "attributes": {
                                "name": "icmp"
                            },
                            "children": [
                                {
                                    "vzSubj": {
                                        "attributes": {
                                            "name": "icmp-subj",
                                            "consMatchT": "AtleastOne",
                                            "provMatchT": "AtleastOne"
                                        },
                                        "children": [
                                            {
                                                "vzRsSubjFiltAtt": {
                                                    "attributes": {
                                                        "tnVzFilterName": "icmp-filter"
                                                    }
                                                }
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
        return path, data


if __name__ == "__main__":
    pass
