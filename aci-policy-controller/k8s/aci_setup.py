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

_log = logging.getLogger("__main__")

def aci_setup(controller):
    """
    Initialize ACI to prepare for kubernetes policy using AIM
    """
    
    t = aim_resource.Tenant(name = controller._aci_tenant)
    t = controller._aim.create(controller._aim_context, t, overwrite=True)

    rd = aim_resource.VRF(tenant_name = controller._aci_tenant,
                          name = ACI_VRF_FMT % controller._aci_tenant)
    rd = controller._aim.create(controller._aim_context, rd, overwrite=True)

    _log.info("Created tenant %s and VRF %s" % (t.dn, rd.dn))
