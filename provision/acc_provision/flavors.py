DEFAULT_FLAVOR = "kubernetes-1.10"

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
        "cnideploy_version": "1.9r36",
        "aci_containers_host_version": "1.9r36",
        "aci_containers_controller_version": "1.9r36",
        "opflex_agent_version": "1.9r65",
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

FLAVORS = {
    # Upstream Kubernetes
    "kubernetes-1.12": {
        "desc": "Kubernetes 1.12",
        "default_version": "1.9",
        "status": "Pre-release",
        "hidden": False,
    },
    "kubernetes-1.11": {
        "desc": "Kubernetes 1.11",
        "default_version": "1.9",
        "status": None,
        "hidden": False,
    },
    "kubernetes-1.10": {
        "desc": "Kubernetes 1.10",
        "default_version": "1.9",
        "status": None,
        "hidden": False,
    },
    "kubernetes-1.9": {
        "desc": "Kubernetes 1.9",
        "default_version": "1.9",
        "status": None,
        "hidden": True,
    },
    "kubernetes-1.8": {
        "desc": "Kubernetes 1.8",
        "default_version": "1.7",
        "config": {
            "kube_config": {
                "use_apps_api": "apps/v1beta2",
                "use_apps_apigroup": "apps",
            }
        },
        "status": None,
        "hidden": True,
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
        },
        "status": None,
        "hidden": True,
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
        },
        "status": None,
        "hidden": True,
    },
    # Red Hat OpenShift Container Platform
    "openshift-3.11": {
        "desc": "Red Hat OpenShift Container Platform 3.11",
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
        "status": "Experimental",
        "hidden": False,
    },
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
        "status": None,
        "hidden": False,
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
        "status": None,
        "hidden": True,
    },
    # Docker Universal Control Plane (UCP)
    "docker-ucp-3.0": {
        "desc": "Docker Universal Control Plane (UCP) 3.0",
        "default_version": "1.9",
        "status": "Pre-release",
        "hidden": False,
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
        "status": None,
        "hidden": False,
    }
}
