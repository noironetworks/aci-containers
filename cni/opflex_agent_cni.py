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

# CNI plugin executable for OpFlex Agent container integration

import json
import sys
import os
import logging
import shutil
import subprocess

from constants.logging import *
from constants.cni import *

errors = {
    'PARAM': 100,
    'INPUT': 101,
    'PATH': 102,
    'OS': 103,
    'IPAM': 104
    }

_log = logging.getLogger("opflex-agent-cni")

# Handle an error by logging it, outputting a properly-formatted error
# response, and exiting with the provided status code
def handleError(message, code, details=None):
    _log.error("(%s) %s: %s", code, message, details)
    json.dump({"cniVersion": CNI_VERSION,
               "code": code,
               "msg": message,
               "details": details}, sys.stdout, indent=2, sort_keys=True)
    print()
    sys.exit(code)

# Execute the IPAM plugin to get IP address information
def executeIPAM(netconfig):
    path=os.environ.get('CNI_PATH', os.environ.get('PATH', os.defpath))
    cniexe = netconfig['ipam']['type']
    exe = shutil.which(cniexe, path=path)
    if exe is None:
        handleError("Could not find CNI plugin executable", errors['PATH'],
                    "%s not found in %s" % (cniexe, path))
    try:
        _log.debug("Running IPAM module \"%s\"" % exe)
        with subprocess.Popen([exe],
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              universal_newlines=True) as proc:
            try:
                (ipamres, ipamerr) = proc.communicate(input=json.dumps(netconfig),
                                                      timeout=30)
                result = json.loads(ipamres)

                if proc.returncode != 0:
                    handleError("Error executing IPAM module", errors['IPAM'],
                                "(%d) %s: %s" %
                                (result.get("code", -1),
                                 result.get("msg", "[No Message]"),
                                 result.get("details", "[No Details]")))
                return result
            except subprocess.TimeoutExpired:
                proc.kill()
                handleError("Timed out executing IPAM module", errors['IPAM'])

    except OSError as e:
        handleError("Could not execute IPAM module %s" % exe, errors['OS'],
                    str(e))
    except json.JSONDecodeError as e:
        handleError("Could not decode IPAM module output: %s" % exe, errors['INPUT'],
                    str(e))
    except Exception as e:
        handleError("Error executing IPAM module: %s" % exe, errors['IPAM'],
                    str(e))
    
def cni_main():
    log_level = os.environ.get("LOG_LEVEL", "info").upper()
    formatter = logging.Formatter(LOG_FORMAT)
    stdout_hdlr = logging.StreamHandler(sys.stderr)
    stdout_hdlr.setFormatter(formatter)
    _log.addHandler(stdout_hdlr)
    _log.setLevel(log_level)

    try:
        netconfig = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        handleError("Invalid JSON input", 101, str(e))
        
    _log.debug('CNI configuration: Container ID: %s, '
               'Interface Name: %s, '
               'Network Namespace: %s, '
               'Config: %s',
               os.environ.get('CNI_CONTAINERID', None),
               os.environ.get('CNI_IFNAME', None),
               os.environ.get('CNI_NETNS', None),
               netconfig)

    for p in ['CNI_CONTAINERID', 'CNI_IFNAME', 'CNI_NETNS']:
        if p not in os.environ:
            handleError("Missing required environment variable",
                        errors['PARAM'], p)

    for p in ['name', 'ipam']:
        if p not in netconfig:
            handleError("Missing required configuration parameter",
                        errors['PARAM'], p)

    if "type" not in netconfig['ipam']:
        handleError("Missing required IPAM configuration parameter",
                    errors['PARAM'], "type")

    ipamresult = executeIPAM(netconfig)
    json.dump(ipamresult, sys.stdout, indent=2, sort_keys=True)
    print()

if __name__ == "__main__":
    cni_main()

