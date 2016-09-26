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

import simplejson as json
import logging
from constants.logging import *
from . namespace import sync_namespace
import policy_cache

_log = logging.getLogger("__main__")

def add_update_pod(controller, pod):
    """
    Called when a Pod update with type ADDED is received.
    """

    namespace_name = pod["metadata"]["namespace"]
    name = pod["metadata"]["name"]

    with controller._policy_cache.lock:
        ns = controller._policy_cache.namespaces.get(namespace_name)
        if ns is None:
            ns = policy_cache.NamespaceState(name=namespace_name)
            controller._policy_cache.namespaces[namespace_name] = ns

        ns.pods[name] = pod

        _log.info("Namespace %s (%s) has %d pods" % (namespace_name, ns.name, len(ns.pods)))

    sync_namespace(controller, namespace_name)

def delete_pod(controller, pod):
    """
    We don't need to do anything when a pod is deleted - the CNI plugin
    handles the deletion of the endpoint.  Just update the caches.
    """

    namespace_name = pod["metadata"]["namespace"]
    name = pod["metadata"]["name"]

    with controller._policy_cache.lock:
        ns = controller._policy_cache.namespaces.get(namespace_name)
        if ns is not None:
            ns.pods.pop(name, None)

    sync_namespace(controller, namespace_name)
