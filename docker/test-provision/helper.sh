#!/bin/sh

echo "\n \
Example: \n

docker run -v /tmp/out:/output --network=host -e "APIC_IP=3.14.41.154" -e "TENANT=e2_kube" -e "REGION=us-east-2" -e 'APIC_PASSWORD=pass!0234' noirolabs/cni-test-provision\
\n\
\n\
Output yamls will be placed in /tmp/out\
\n"

