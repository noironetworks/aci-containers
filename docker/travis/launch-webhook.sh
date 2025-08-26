#!/bin/bash

set -e
set -x

if [ -z $REQUIRE_NAD_ANNOTATION ]; then
   REQUIRE_NAD_ANNOTATION=$false
elif [ "$REQUIRE_NAD_ANNOTATION" == "false" ]; then
   REQUIRE_NAD_ANNOTATION=$false
else
   REQUIRE_NAD_ANNOTATION="-require-nad-annotation"
fi

if [ -z $VMM_LITE_ENABLED ]; then
   VMM_LITE_ENABLED=$false
elif [ "$VMM_LITE_ENABLED" == "false" ]; then
   VMM_LITE_ENABLED=$false
else
   VMM_LITE_ENABLED="-vmm-lite-enabled"
fi

if [ -z $CHAINED_MODE_ENABLED ]; then
   CHAINED_MODE_ENABLED=$false
elif [ "$CHAINED_MODE_ENABLED" == "false" ]; then
   CHAINED_MODE_ENABLED=$false
else
   CHAINED_MODE_ENABLED="-chained-mode-enabled"
fi

if [ -z $CONTAINER_FOR_ENVVARS ]; then
   CONTAINER_NAME_FOR_ENVVARS=$false
else
   CONTAINER_NAME_FOR_ENVVARS="-container-name-for-envvars "$CONTAINER_FOR_ENVVARS
fi

/usr/local/bin/aci-containers-webhook $REQUIRE_NAD_ANNOTATION $VMM_LITE_ENABLED $CHAINED_MODE_ENABLED $CONTAINER_NAME_FOR_ENVVARS
