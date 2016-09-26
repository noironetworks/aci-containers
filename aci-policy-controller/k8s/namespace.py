# Copyright (c) 2015-2016 Tigera Inc.  All rights reserved.
# Copyright (c) 2016 Cisco Systems, Inc.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import simplejson as json

from aim.api import resource as aim_resource
from aim import context as aim_context

from constants.k8s import *
from constants.aim import *
import policy_cache
import six

_log = logging.getLogger("__main__")

def sync_namespaces(controller):
    for n in controller._policy_cache.namespaces.keys():
        sync_namespace(controller, n)

def get_labels_from_selector(active_labels, selector):
    match_labels = selector.get("matchLabels")
    if isinstance(match_labels, dict):
        for k in match_labels.keys():
            if isinstance(k, string):
                active_labels[k] = True
    match_expressions = selector.get("matchExpressions")
    if isinstance(match_expressions, list):
        for r in match_expressions:
            key = r.get("key")
            if isinstance(key, string):
                active_labels[key] = True

def sync_eg_map(controller, namespace_name, eg_map):
    existing = controller._aim.find(controller._aim_context,
                                    aim_resource.EndpointGroup,
                                    tenant_name=controller._aci_tenant,
                                    app_profile_name=ACI_AP_FMT % namespace_name)

    for existing_eg in existing:
        if existing_eg.name not in eg_map:
            _log.info("Cleaning %s/%s", namespace_name, existing_eg.name)
            eg = controller._aim.delete(controller._aim_context, existing_eg)

    for eg_name, pods in six.iteritems(eg_map):
        eg = aim_resource.\
             EndpointGroup(tenant_name = controller._aci_tenant,
                           app_profile_name=ACI_AP_FMT % namespace_name,
                           bd_name=ACI_BD_FMT % controller._aci_tenant,
                           name = eg_name)
        eg = controller._aim.create(controller._aim_context, eg, overwrite=True)


def sync_namespace(controller, namespace_name):
    _log.info("Syncing namespace %s", namespace_name)

    with controller._policy_cache.lock:
	ns = controller._policy_cache.namespaces.get(namespace_name)
	if not isinstance(ns, policy_cache.NamespaceState):
            _log.info("Deleted namespace %s" % namespace_name)
	    sync_eg_map(controller, namespace_name, {})

	    ap = aim_resource.\
	         ApplicationProfile(tenant_name = controller._aci_tenant,
	                            name = ACI_AP_FMT % namespace_name)
	    controller._aim.delete(controller._aim_context, ap)
	    return

	ap = aim_resource.\
	     ApplicationProfile(tenant_name = controller._aci_tenant,
	                        name = ACI_AP_FMT % namespace_name)
	ap = controller._aim.create(controller._aim_context, ap, overwrite=True)

	eg_map = {}
	if not ns.isolated:
            _log.info("unisolated ns %s", ns.name)
	    eg_map[ACI_EG_FMT % "unisolated"] = ns.pods

	    sync_eg_map(controller, namespace_name, eg_map)

	    return


	active_labels = {}
	for n, np in six.iteritems(ns.network_policies):
	    spec = pod.get("spec")
	    if not isinstance(spec, dict):
	        continue
	    pod_selector = spec.get("podSelector")
	    if isinstance(pod_selector, dict):
	        get_labels_from_selector(active_labels, pod_selector)

	_log.info(active_labels)

	label_groups = {}
	for n, pod in six.iteritems(ns.pods):
	    _log.info(n)


	#namespace = pod["metadata"]["namespace"]
	#name = pod["metadata"]["name"]
	#labels = pod["metadata"].get("labels", {})


def add_update_namespace(controller, namespace):
    """
    Configures the necessary policy in Calico for this namespace.
    Uses the network policy annotation.
    """
    namespace_name = namespace["metadata"]["name"]
    _log.debug("Adding/updating namespace: %s", namespace_name)

    # Determine the type of network-isolation specified by this namespace.
    # This defaults to no isolation.
    annotations = namespace["metadata"].get("annotations", {})
    _log.debug("Namespace %s has annotations: %s", namespace_name, annotations)
    policy_annotation = annotations.get(NS_POLICY_ANNOTATION, "{}")
    try:
        policy_annotation = json.loads(policy_annotation)
    except ValueError, TypeError:
        _log.exception("Failed to parse namespace annotations: %s", annotations)
        return

    # Parsed the annotation - get data.  Might not be a dict, so be careful
    # to catch an AttributeError if it has no get() method.
    try:
        ingress_isolation = policy_annotation.get("ingress",
                                                  {}).get("isolation", "")
    except AttributeError:
        _log.exception("Invalid namespace annotation: %s", policy_annotation)
        return

    isolate_ns = ingress_isolation == "DefaultDeny"
    _log.debug("Namespace %s has %s.  Isolate=%s",
               namespace_name, ingress_isolation, isolate_ns)

    with controller._policy_cache.lock:
	ns = controller._policy_cache.namespaces.get(namespace_name)
	if ns is None:
	    ns = policy_cache.NamespaceState(name=namespace_name)
	    controller._policy_cache.namespaces[namespace_name] = ns

	ns.isolated = isolate_ns

    sync_namespace(controller, namespace_name)


def delete_namespace(controller, namespace):
    """
    Takes a deleted namespace and removes the corresponding
    configuration from the AIM policy.
    """
    namespace_name = namespace["metadata"]["name"]

    with controller._policy_cache.lock:
        controller._policy_cache.namespaces.pop(namespace_name, None)

    sync_namespace(controller, namespace_name)
