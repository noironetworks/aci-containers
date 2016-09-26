#
# Copyright (c) 2015-2016 Tigera Inc.  All rights reserved.
# Copyright (c) 2016 Cisco Systems, Inc. and others.  All rights reserved.
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

# Default Kubernetes API value.
DEFAULT_API = "https://kubernetes.default:443"

# Path to the CA certificate (if it exists).
CA_CERT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# Resource types.
RESOURCE_TYPE_NETWORK_POLICY = "NetworkPolicy"
RESOURCE_TYPE_POD = "Pod"
RESOURCE_TYPE_NAMESPACE = "Namespace"

# API paths to NetworkPolicy objects.
BETA_API = "%s/apis/extensions/v1beta1"
NET_POLICY_PATH = BETA_API + "/networkpolicies"
NET_POLICY_WATCH_PATH = BETA_API + "/watch/networkpolicies"

# Mapping of resource to api URL.
GET_URLS = {RESOURCE_TYPE_POD: "%s/api/v1/pods",
            RESOURCE_TYPE_NAMESPACE: "%s/api/v1/namespaces",
            RESOURCE_TYPE_NETWORK_POLICY: NET_POLICY_PATH}
WATCH_URLS = {RESOURCE_TYPE_POD: "%s/api/v1/watch/pods",
              RESOURCE_TYPE_NAMESPACE: "%s/api/v1/watch/namespaces",
              RESOURCE_TYPE_NETWORK_POLICY: NET_POLICY_WATCH_PATH}

# Annotation to look for network-isolation on namespaces.
NS_POLICY_ANNOTATION = "net.beta.kubernetes.io/network-policy"

# Environment variables for getting the Kubernetes API.
K8S_SERVICE_PORT = "KUBERNETES_SERVICE_PORT"
K8S_SERVICE_HOST = "KUBERNETES_SERVICE_HOST"

# Max number of updates to queue.
# Assuming 100 pods per host, 1000 hosts, we may queue
# about 100,000 updates at start of day.
MAX_QUEUE_SIZE = 100000

# Seconds to wait when adding to a full queue.
# It should easily not take more than a second to complete processing of
# an event off the queue.  Allow for five times that much to be safe.
QUEUE_PUT_TIMEOUT = 5

# Update types.
TYPE_ADDED = "ADDED"
TYPE_MODIFIED = "MODIFIED"
TYPE_DELETED = "DELETED"
TYPE_ERROR = "ERROR"
