from __future__ import print_function

import json
import sys

import requests
import urllib3
import ipaddress

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
apic_debug = False
apic_default_timeout = (15, 90)


def err(msg):
    print("ERR:  " + msg, file=sys.stderr)


def warn(msg):
    print("WARN: " + msg, file=sys.stderr)


def dbg(msg):
    if apic_debug:
        print("DBG:  " + msg, file=sys.stderr)


def yesno(flag):
    if flag:
        return "yes"
    return "no"


def aci_obj(klass, **kwargs):
    children = kwargs.pop('_children', None)
    data = {klass: {'attributes': kwargs}}
    if children:
        data[klass]['children'] = children
    return data


class Apic(object):
    def __init__(self, addr, username, password,
                 ssl=True, verify=False, timeout=None, debug=False):
        global apic_debug
        apic_debug = debug
        self.addr = addr
        self.ssl = ssl
        self.username = username
        self.password = password
        self.cookies = None
        self.errors = 0
        self.verify = verify
        self.timeout = timeout if timeout else apic_default_timeout
        self.debug = debug
        self.login()

    def url(self, path):
        if self.ssl:
            return 'https://%s%s' % (self.addr, path)
        return 'http://%s%s' % (self.addr, path)

    def get(self, path, data=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        args.update(timeout=self.timeout)
        return requests.get(self.url(path), **args)

    def post(self, path, data):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        args.update(timeout=self.timeout)
        return requests.post(self.url(path), **args)

    def delete(self, path, data=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        args.update(timeout=self.timeout)
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

    def get_path(self, path, multi=False):
        ret = None
        try:
            resp = self.get(path)
            self.check_resp(resp)
            respj = json.loads(resp.text)
            if len(respj["imdata"]) > 0:
                if multi:
                    ret = respj["imdata"]
                else:
                    ret = respj["imdata"][0]
        except Exception as e:
            self.errors += 1
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
            warn("User already exists (%s), recreating user" % sync_login)
            user_path = "/api/node/mo/uni/userext/user-%s.json" % sync_login
            resp = self.delete(user_path)
            dbg("%s: %s" % (user_path, resp.text))

        for path, config in data:
            try:
                if path in ignore_list:
                    continue
                if config is not None:
                    resp = self.post(path, config)
                    self.check_resp(resp)
                    dbg("%s: %s" % (path, resp.text))
            except Exception as e:
                # log it, otherwise ignore it
                self.errors += 1
                err("Error in provisioning %s: %s" % (path, str(e)))

    def unprovision(self, data, system_id, tenant):
        for path, config in data:
            try:
                if path.split("/")[-1].startswith("instP-"):
                    continue
                if path not in [
                        "/api/mo/uni/infra.json",
                        "/api/mo/uni/tn-common.json",
                ]:
                    resp = self.delete(path)
                    self.check_resp(resp)
                    dbg("%s: %s" % (path, resp.text))
            except Exception as e:
                # log it, otherwise ignore it
                self.errors += 1
                err("Error in un-provisioning %s: %s" % (path, str(e)))

        # Finally clean any stray resources in common
        self.clean_tagged_resources(system_id, tenant)

    def valid_tagged_resource(self, tag, system_id, tenant):
        ret = False
        prefix = "%s-" % system_id
        if tag.startswith(prefix):
            tagid = tag[len(prefix):]
            if len(tagid) == 32:
                try:
                    int(tagid, base=16)
                    ret = True
                except ValueError:
                    ret = False
        return ret

    def clean_tagged_resources(self, system_id, tenant):
        tags = {}
        tags_path = "/api/node/mo/uni/tn-%s.json" % (tenant,)
        tags_path += "?query-target=subtree&target-subtree-class=tagInst"
        tags_list = self.get_path(tags_path, multi=True)
        if tags_list is not None:
            for tag_mo in tags_list:
                tag_name = tag_mo["tagInst"]["attributes"]["name"]
                if self.valid_tagged_resource(tag_name, system_id, tenant):
                    tags[tag_name] = True
                    dbg("Deleting tag: %s" % tag_name)
                else:
                    dbg("Ignoring tag: %s" % tag_name)

        mos = {}
        for tag in tags.keys():
            dbg("Objcts selected for tag: %s" % tag)
            mo_path = "/api/tag/%s.json" % tag
            mo_list = self.get_path(mo_path, multi=True)
            for mo_dict in mo_list:
                for mo_key in mo_dict.keys():
                    mo = mo_dict[mo_key]
                    mo_dn = mo["attributes"]["dn"]
                    mos[mo_dn] = True
                    dbg("    - %s" % mo_dn)

        for mo_dn in sorted(mos.keys(), reverse=True):
            mo_path = "/api/node/mo/%s.json" % mo_dn
            dbg("Deleting object: %s" % mo_dn)
            self.delete(mo_path)


class ApicKubeConfig(object):
    def __init__(self, config):
        self.config = config
        self.use_kubeapi_vlan = True
        self.tenant_generator = 'kube_tn'
        self.associate_aep_to_nested_inside_domain = False

    def get_nested_domain_type(self):
        inside = self.config["aci_config"]["vmm_domain"].get("nested_inside")
        if not inside:
            return None
        t = inside.get("type")
        if t and t.lower() == "vmware":
            return "VMware"
        return t

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
        update(data, self.pdom_pool())
        update(data, self.vdom_pool())
        update(data, self.mcast_pool())
        update(data, self.phys_dom())
        update(data, self.kube_dom())
        update(data, self.nested_dom())
        update(data, self.associate_aep())
        update(data, self.opflex_cert())

        update(data, self.common_tn())
        update(data, getattr(self, self.tenant_generator)())
        for l3out_instp in self.config["aci_config"]["l3out"]["external_networks"]:
            update(data, self.l3out_contract(l3out_instp))

        update(data, self.kube_user())
        update(data, self.kube_cert())
        return data

    def pdom_pool(self):
        pool_name = self.config["aci_config"]["physical_domain"]["vlan_pool"]
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
                                "from": "vlan-%s" % service_vlan,
                                "to": "vlan-%s" % service_vlan
                            }
                        },
                    },
                ]
            }
        }
        if self.use_kubeapi_vlan:
            kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
            data["fvnsVlanInstP"]["children"].insert(
                0,
                {
                    "fvnsEncapBlk": {
                        "attributes": {
                            "allocMode": "static",
                            "from": "vlan-%s" % kubeapi_vlan,
                            "to": "vlan-%s" % kubeapi_vlan
                        }
                    }
                })
        return path, data

    def vdom_pool(self):
        encap_type = self.config["aci_config"]["vmm_domain"]["encap_type"]
        vpool_name = self.config["aci_config"]["vmm_domain"]["vlan_pool"]
        vlan_range = self.config["aci_config"]["vmm_domain"]["vlan_range"]

        if encap_type != "vlan":
            return None

        path = "/api/mo/uni/infra/vlanns-[%s]-dynamic.json" % vpool_name
        data = {
            "fvnsVlanInstP": {
                "attributes": {
                    "name": vpool_name,
                    "allocMode": "dynamic"
                },
                "children": [
                    {
                        "fvnsEncapBlk": {
                            "attributes": {
                                "allocMode": "dynamic",
                                "from": "vlan-%s" % vlan_range["start"],
                                "to": "vlan-%s" % vlan_range["end"],
                            }
                        }
                    },
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
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        encap_type = self.config["aci_config"]["vmm_domain"]["encap_type"]
        mcast_fabric = self.config["aci_config"]["vmm_domain"]["mcast_fabric"]
        mpool_name = self.config["aci_config"]["vmm_domain"]["mcast_pool"]
        vpool_name = self.config["aci_config"]["vmm_domain"]["vlan_pool"]
        kube_controller = self.config["kube_config"]["controller"]

        mode = "k8s"
        scope = "kubernetes"
        if vmm_type == "OpenShift":
            mode = "openshift"
            scope = "openshift"
        elif vmm_type == "CloudFoundry":
            mode = "cf"
            scope = "cloudfoundry"

        path = "/api/mo/uni/vmmp-%s/dom-%s.json" % (vmm_type, vmm_name)
        data = {
            "vmmDomP": {
                "attributes": {
                    "name": vmm_name,
                    "mode": mode,
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
                                "mode": mode,
                                "scope": scope,
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
        if encap_type == "vlan":
            vlan_pool_data = {
                "infraRsVlanNs": {
                    "attributes": {
                        "tDn": "uni/infra/vlanns-[%s]-dynamic" % vpool_name
                    }
                }
            }
            data["vmmDomP"]["children"].append(vlan_pool_data)
        return path, data

    def nested_dom(self):
        nvmm_type = self.get_nested_domain_type()
        if nvmm_type != "VMware":
            return

        system_id = self.config["aci_config"]["system_id"]
        nvmm_name = (self.config["aci_config"]["vmm_domain"]
                     ["nested_inside"]["name"])
        encap_type = self.config["aci_config"]["vmm_domain"]["encap_type"]
        infra_vlan = self.config["net_config"]["infra_vlan"]
        service_vlan = self.config["net_config"]["service_vlan"]

        path = ("/api/mo/uni/vmmp-%s/dom-%s/usrcustomaggr-%s.json" %
                (nvmm_type, nvmm_name, system_id))
        data = {
            "vmmUsrCustomAggr": {
                "attributes": {
                    "name": system_id,
                    "promMode": "Enabled",
                },
                "children": [
                    {
                        "fvnsEncapBlk": {
                            "attributes": {
                                "from": "vlan-%d" % infra_vlan,
                                "to": "vlan-%d" % infra_vlan,
                            }
                        }
                    },
                    {
                        "fvnsEncapBlk": {
                            "attributes": {
                                "from": "vlan-%d" % service_vlan,
                                "to": "vlan-%d" % service_vlan,
                            }
                        }
                    },
                ]
            }
        }
        if self.use_kubeapi_vlan:
            kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
            data["vmmUsrCustomAggr"]["children"].append(
                {
                    "fvnsEncapBlk": {
                        "attributes": {
                            "from": "vlan-%d" % kubeapi_vlan,
                            "to": "vlan-%d" % kubeapi_vlan,
                        }
                    }
                })
        if encap_type == "vlan":
            vlan_range = self.config["aci_config"]["vmm_domain"]["vlan_range"]
            data["vmmUsrCustomAggr"]["children"].append({
                "fvnsEncapBlk": {
                    "attributes": {
                        "from": "vlan-%d" % vlan_range["start"],
                        "to": "vlan-%d" % vlan_range["end"],
                    }
                },
            })
        return path, data

    def associate_aep(self):
        aep_name = self.config["aci_config"]["aep"]
        phys_name = self.config["aci_config"]["physical_domain"]["domain"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        infra_vlan = self.config["net_config"]["infra_vlan"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]

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
                                "tDn": "uni/vmmp-%s/dom-%s" % (vmm_type, vmm_name)
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
                ]
            }
        }
        if self.use_kubeapi_vlan:
            kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
            data["infraAttEntityP"]["children"].append(
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
                })

        base = '/api/mo/uni/infra/attentp-%s' % aep_name
        rsvmm = base + '/rsdomP-[uni/vmmp-%s/dom-%s].json' % (vmm_type, vmm_name)
        rsphy = base + '/rsdomP-[uni/phys-%s].json' % phys_name

        if self.associate_aep_to_nested_inside_domain:
            nvmm_name = (
                self.config["aci_config"]["vmm_domain"]["nested_inside"]["name"])
            nvmm_type = self.get_nested_domain_type()
            data["infraAttEntityP"]["children"].append(
                {
                    "infraRsDomP": {
                        "attributes": {
                            "tDn": "uni/vmmp-%s/dom-%s" % (nvmm_type, nvmm_name)
                        }
                    }
                })
            rsnvmm = (base + '/rsdomP-[uni/vmmp-%s/dom-%s].json' %
                      (nvmm_type, nvmm_name))
            return path, data, rsvmm, rsnvmm, rsphy
        else:
            rsfun = (base + '/gen-default/rsfuncToEpg-'
                     '[uni/tn-%s/ap-kubernetes/epg-kube-nodes].json' % (tn_name))
            return path, data, rsvmm, rsphy, rsfun

    def opflex_cert(self):
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

    def l3out_contract(self, l3out_instp):
        system_id = self.config["aci_config"]["system_id"]
        vrf_tenant = self.config["aci_config"]["vrf"]["tenant"]
        l3out = self.config["aci_config"]["l3out"]["name"]
        l3out_rsprov_name = "%s-l3out-allow-all" % system_id

        pathc = (vrf_tenant, l3out, l3out_instp)
        path = "/api/mo/uni/tn-%s/out-%s/instP-%s.json" % pathc
        data = {
            "fvRsProv": {
                "attributes": {
                    "matchT": "AtleastOne",
                    "tnVzBrCPName": l3out_rsprov_name
                }
            }
        }

        rsprovc = (vrf_tenant, l3out, l3out_instp, l3out_rsprov_name)
        rsprov = "/api/mo/uni/tn-%s/out-%s/instP-%s/rsprov-%s.json" % rsprovc
        return path, data, rsprov

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
        try:
            with open(certfile, "r") as cfile:
                cert = cfile.read()
        except IOError:
            # Ignore error in reading file, it will be logged if/when used
            pass

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
        if cert is None:
            data = None
        return path, data

    def isV6(self):
        pod_cidr = self.config["net_config"]["pod_subnet"]
        rtr, mask = pod_cidr.split('/')
        ip = ipaddress.ip_address(unicode(rtr))
        if ip.version == 4:
            return False
        else:
            return True

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
        kade = self.config["kube_config"].get("allow_kube_api_default_epg")
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        v6subnet = self.isV6()

        kube_default_children = [
            {
                "fvRsDomAtt": {
                    "attributes": {
                        "tDn": "uni/vmmp-%s/dom-%s" % (vmm_type, vmm_name)
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
                "fvRsBd": {
                    "attributes": {
                        "tnFvBDName": "kube-pod-bd"
                    }
                }
            }
        ]

        if kade is True:
            kube_default_children.append({
                "fvRsCons": {
                    "attributes": {
                        "tnVzBrCPName": "kube-api"
                    }
                }
            })

        node_subnet_obj = {
            "attributes": {
                "ip": node_subnet,
                "scope": "public",
            }
        }
        pod_subnet_obj = {
            "attributes": {
                "ip": pod_subnet,
            }
        }
        if v6subnet:
            ipv6_nd_policy_rs = [{
                "fvRsNdPfxPol": {
                    "attributes": {
                        "tnNdPfxPolName": "kube-nd-ra-policy"
                    }
                }
            }]
            node_subnet_obj['attributes']['ctrl'] = 'nd'
            node_subnet_obj["children"] = ipv6_nd_policy_rs
            pod_subnet_obj['attributes']['ctrl'] = 'nd'
            pod_subnet_obj["children"] = ipv6_nd_policy_rs

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
                                        "children": kube_default_children
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
                                                        "tDn": "uni/vmmp-%s/dom-%s" % (vmm_type, vmm_name)
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
                                                        "tnVzBrCPName": "dns"
                                                    }
                                                }
                                            },
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
                                "name": "kube-node-bd",
                                "arpFlood": yesno(True)
                            },
                            "children": [
                                {
                                    "fvSubnet": node_subnet_obj,
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
                                    "fvSubnet": pod_subnet_obj,
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
                                "name": "icmp-filter"
                            },
                            "children": [
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "icmp",
                                            "etherT": "ipv4",
                                            "prot": "icmp"
                                        }
                                    }
                                },
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "icmp6",
                                            "etherT": "ipv6",
                                            "prot": "icmpv6"
                                        }
                                    }
                                },
                            ]
                        }
                    },
                    {
                        "vzFilter": {
                            "attributes": {
                                "name": "health-check-filter-in"
                            },
                            "children": [
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "health-check",
                                            "etherT": "ip",
                                            "prot": "tcp",
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
                                "name": "health-check-filter-out"
                            },
                            "children": [
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "health-check",
                                            "etherT": "ip",
                                            "prot": "tcp",
                                            "stateful": "no",
                                            "tcpRules": "est"
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
                                },
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
                                },
                                {
                                    "vzEntry": {
                                        "attributes": {
                                            "name": "kube-api2",
                                            "etherT": "ip",
                                            "prot": "tcp",
                                            "dFromPort": "8443",
                                            "dToPort": "8443",
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
                                            "revFltPorts": "yes",
                                            "consMatchT": "AtleastOne",
                                            "provMatchT": "AtleastOne"
                                        },
                                        "children": [
                                            {
                                                "vzOutTerm": {
                                                    "attributes": {
                                                        "name": ""
                                                    },
                                                    "children": [
                                                        {
                                                            "vzRsFiltAtt": {
                                                                "attributes": {
                                                                    "tnVzFilterName": "health-check-filter-out"
                                                                }
                                                            }
                                                        }
                                                    ]
                                                }
                                            },
                                            {
                                                "vzInTerm": {
                                                    "attributes": {
                                                        "name": ""
                                                    },
                                                    "children": [
                                                        {
                                                            "vzRsFiltAtt": {
                                                                "attributes": {
                                                                    "tnVzFilterName": "health-check-filter-in"
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

        if v6subnet is True:
            data["fvTenant"]["children"].append({
                "ndPfxPol": {
                    "attributes": {
                        "ctrl": "on-link,router-address",
                        "lifetime": "2592000",
                        "name": "kube-nd-ra-policy",
                        "prefLifetime": "604800"
                    }
                }
            })

        # If dhcp_relay_label is present, attach the label to the kube-node-bd
        if "dhcp_relay_label" in self.config["aci_config"]:
            dbg("Handle DHCP Relay Label")
            children = data['fvTenant']['children']
            dhcp_relay_label = self.config["aci_config"]["dhcp_relay_label"]
            attr = {
                "dhcpLbl": {
                    "attributes": {
                        "name": dhcp_relay_label,
                        "owner": "infra"
                    }
                }
            }
            # lookup kube-node-bd data
            for child in children:
                if 'fvBD' in child:
                    if child['fvBD']['attributes']['name'] == 'kube-node-bd':
                        child['fvBD']["children"].append(attr)
                        break
        return path, data

    def epg(self, name, bd_name, provides=[], consumes=[], phy_domains=[],
            vmm_domains=[]):
        children = []
        if bd_name:
            children.append(aci_obj('fvRsBd', tnFvBDName=bd_name))
        for c in consumes:
            children.append(aci_obj('fvRsCons', tnVzBrCPName=c))
        for p in provides:
            children.append(aci_obj('fvRsProv', tnVzBrCPName=p))
        for (d, e) in phy_domains:
            children.append(aci_obj('fvRsDomAtt', encap="vlan-%s" % e,
                                    tDn="uni/phys-%s" % d))
        for (t, n) in vmm_domains:
            children.append(aci_obj('fvRsDomAtt',
                                    tDn="uni/vmmp-%s/dom-%s" % (t, n)))
        return aci_obj('fvAEPg', name=name, _children=children)

    def bd(self, name, vrf_name, subnets=[], l3outs=[]):
        children = []
        for sn in subnets:
            children.append(aci_obj('fvSubnet', ip=sn, scope="public"))
        if vrf_name:
            children.append(aci_obj('fvRsCtx', tnFvCtxName=vrf_name))
        for l in l3outs:
            children.append(aci_obj('fvRsBDToOut', tnL3extOutName=l))
        return aci_obj('fvBD', name=name, _children=children)

    def filter(self, name, entries=[]):
        children = []
        for e in entries:
            children.append(aci_obj('vzEntry', **e))
        return aci_obj('vzFilter', name=name, _children=children)

    def contract(self, name, subjects=[]):
        children = []
        for s in subjects:
            filts = []
            for f in s.get('filters', []):
                filts.append(aci_obj('vzRsSubjFiltAtt', tnVzFilterName=f))
            subj = aci_obj('vzSubj', name=s['name'],
                           consMatchT="AtleastOne",
                           provMatchT="AtleastOne",
                           _children=filts)
            children.append(subj)
        return aci_obj('vzBrCP', name=name, _children=children)

    def cloudfoundry_tn(self):
        system_id = self.config["aci_config"]["system_id"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        cf_vrf = self.config["aci_config"]["vrf"]["name"]
        cf_l3out = self.config["aci_config"]["l3out"]["name"]
        node_subnet = self.config["net_config"]["node_subnet"]
        pod_subnet = self.config["net_config"]["pod_subnet"]
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        nvmm_name = (
            self.config["aci_config"]["vmm_domain"]["nested_inside"]["name"])
        nvmm_type = self.get_nested_domain_type()
        ap_name = (self.config["cf_config"]["default_endpoint_group"]
                   ["app_profile"])
        app_epg_name = (
            self.config["cf_config"]["default_endpoint_group"]["group"])

        app_default_epg = self.epg(app_epg_name,
                                   "cf-app-bd",
                                   provides=["gorouter"],
                                   consumes=["dns",
                                             "%s-l3out-allow-all" % system_id],
                                   vmm_domains=[(vmm_type, vmm_name)])
        node_epg = self.epg(
            self.config["cf_config"]["node_epg"],
            "cf-node-bd",
            provides=["dns"],
            consumes=["gorouter", "%s-l3out-allow-all" % system_id],
            vmm_domains=[(nvmm_type, nvmm_name)])
        ap = aci_obj('fvAp',
                     name=ap_name,
                     _children=[node_epg, app_default_epg])

        app_bd = self.bd('cf-app-bd', cf_vrf,
                         subnets=[pod_subnet],
                         l3outs=[cf_l3out])

        node_bd = self.bd('cf-node-bd', cf_vrf,
                          subnets=[node_subnet],
                          l3outs=[cf_l3out])

        tcp_all_filter = self.filter(
            'tcp-all',
            entries=[dict(name='tcp', etherT='ip', prot='tcp')])
        dns_filter = self.filter(
            'dns',
            entries=[dict(name='udp', etherT='ip', prot='udp',
                          dFromPort='dns', dToPort='dns'),
                     dict(name='tcp', etherT='ip', prot='tcp',
                          dFromPort='dns', dToPort='dns')])

        gorouter_contract = self.contract(
            'gorouter',
            subjects=[dict(name='gorouter-subj', filters=['tcp-all'])])
        dns_contract = self.contract(
            'dns',
            subjects=[dict(name='dns-subj', filters=['dns'])])

        path = "/api/mo/uni/tn-%s.json" % tn_name
        data = aci_obj('fvTenant',
                       name=tn_name,
                       dn="uni/tn-%s" % tn_name,
                       _children=[ap, node_bd, app_bd,
                                  tcp_all_filter, dns_filter,
                                  gorouter_contract, dns_contract])
        return path, data


if __name__ == "__main__":
    pass
