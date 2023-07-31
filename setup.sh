rm -rf dist-static/*
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 make container-operator
docker tag noiro/aci-containers-operator:latest quay.io/noirolabs/aci-containers-operator:abhishek
docker push quay.io/noirolabs/aci-containers-operator:abhishek
