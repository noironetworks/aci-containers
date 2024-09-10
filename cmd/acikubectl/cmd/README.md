# Proactive Configuration with acikubectl

- [Command](#command)
- [Examples](#examples)

# Command
```
acikubectl proactive_policy --help
Do override configuration like changing vmm epg attachment mode

Usage:
  acikubectl proactive_policy create/delete/verify [flags]

Examples:
proactive_policy create/delete

Flags:
  -a, --apic-hosts strings          APIC Hosts
  -p, --apic-passwd string          APIC password
  -u, --apic-user string            APIC username
  -h, --help                        help for proactive_policy
  -e, --vmm-epg-attachment string   Enable immediate/on-demand deployment and resolution immediacy on vmm-epg-attachment (default "on-demand")

Global Flags:
      --context string      Kubernetes context to use for CLI requests.
      --kubeconfig string   Path to the kubeconfig file to use for CLI requests. (default "/home/noiro/kubeconfig")
```

# Examples
The acc-provision created certificate and key files must be available in the working directory, else the username and password to access the APIC can be explicitly provided using the -u and -p arguments.
## Create Proactive Policy

### Immediate
#### Command
```acikubectl proactive_policy create  -e immediate```
#### Output
```
[{"fvRsDomAtt":{"attributes":{"dn":"uni/tn-ocp412/ap-aci-containers-ocp412/epg-aci-containers-default/rsdomAtt-[uni/vmmp-OpenShift/dom-ocp412]","instrImedcy":"immediate","resImedcy":"pre-provision","tDn":"uni/vmmp-OpenShift/dom-ocp412"}}}]
applied!
```

### On-Demand
#### Command:
```acikubectl proactive_policy create  -e on-demand```
#### Output:
```
[{"fvRsDomAtt":{"attributes":{"dn":"uni/tn-ocp412/ap-aci-containers-ocp412/epg-aci-containers-default/rsdomAtt-[uni/vmmp-OpenShift/dom-ocp412]","instrImedcy":"lazy","resImedcy":"lazy","tDn":"uni/vmmp-OpenShift/dom-ocp412"}}}]
applied!
```


## Verify proactive policy
### Command
```
acikubectl proactive_policy verify
 ```

### Output
```
Found pv attachment(topology/pod-2/protpaths-401-402/pathep-[esx-3-HX_vC-vpc],node-401,uni/tn-ocp412/ap-aci-containers-mpod4/epg-aci-containers-default)
Found pv attachment(topology/pod-2/protpaths-401-402/pathep-[esx-3-HX_vC-vpc],node-402,uni/tn-ocp412/ap-aci-containers-mpod4/epg-aci-containers-default)
VERIFY SUCCESS! 
```
## Delete proactive policy
### Command
    ```
    acikubectl proactive_policy delete
    ```
### Output
    ```
    [{"fvRsDomAtt":{"attributes":{"dn":"uni/tn-ocp412/ap-aci-containers-ocp412/epg-aci-containers-default/rsdomAtt-[uni/vmmp-OpenShift/dom-ocp412]","instrImedcy":"lazy","resImedcy":"lazy","tDn":"uni/vmmp-OpenShift/dom-ocp412"}}}]
    applied!
    ```

## With username/password
* ```acikubectl proactive_policy create  -e immediate -u <username> -p <password>```
* ```acikubectl proactive_policy create  -e on-demand -u <username> -p <password>```
* ``` acikubectl proactive_policy delete -u <username> -p <password>```
* ```acikubectl proactive_policy verify -u <username> -p <password>```
* ```acikubectl proactive_policy delete -u <username> -p <password>```


    