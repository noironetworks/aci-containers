# Install

Install using pip as:
```
  pip install acc_provision
```

# Running

```
usage: acc_provision [-h] [-c] [-o] [-a] [-d] [-s] [-u] [-p] [-v]

Provision an ACI kubernetes installation

optional arguments:
  -h, --help        show this help message and exit
  -c , --config     Input file with your fabric configuration
  -o , --output     Output file for your kubernetes deployment
  -a, --apic        Create/Validate the required APIC resources
  -d, --delete      Delete the APIC resources that would have be created
  -s, --sample      Print a sample input file with fabric configuration
  -u , --username   APIC admin username to use for APIC API access
  -p , --password   APIC admin password to use for APIC API access
  -v, --verbose     Enable debug

```
