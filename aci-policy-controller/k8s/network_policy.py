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
import os

from constants.logging import *
from . namespace import sync_namespace

_log = logging.getLogger("__main__")

from aim.api import resource as aim_resource
from aim import context as aim_context

def add_update_network_policy(controller, policy):
    """
    Takes a new network policy from the Kubernetes API and
    creates the corresponding Calico policy configuration.
    """

    namespace = policy["metadata"]["namespace"]
    name = policy["metadata"]["name"]

    with controller._policy_cache.lock:
        ns = controller._policy_cache.namespaces.get(namespace)
        if ns is None:
            ns = policy_cache.NamespaceState(name=namespace_name)
            controller._policy_cache.namespaces[namespace_name] = ns

        ns.network_policies[name] = policy

    sync_namespace(controller, namespace)

def delete_network_policy(controller, policy):
    """
    Takes a deleted network policy and removes the corresponding
    configuration from the Calico datastore.
    """
    namespace = policy["metadata"]["namespace"]
    name = policy["metadata"]["name"]

    with controller._policy_cache.lock:
        ns = controller._policy_cache.namespaces.get(namespace)
        if ns is not None:
            ns.network_policies.pop(name, None)

    sync_namespace(controller, namespace)
