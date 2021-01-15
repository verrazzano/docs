---
title: kind
description: Instructions for setting up a kind cluster for Verrazzano
linkTitle: kind
Weight: 8
draft: false
---

### Prepare for the kind install


* Create the kind cluster 

```shell
kind create cluster --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.18.8@sha256:f4bcc97a0ad6e7abaf3f643d890add7efe6ee4ab90baeb374b4f41a4c95567eb
    kubeadmConfigPatches:
    - |
      kind: InitConfiguration
      nodeRegistration:
        kubeletExtraArgs:
          node-labels: "ingress-ready=true"
          authorization-mode: "AlwaysAllow"
    extraPortMappings:
      - containerPort: 80
        hostPort: 80
        listenAddress: "0.0.0.0"
        protocol: tcp
      - containerPort: 443
        hostPort: 443
        listenAddress: "0.0.0.0"
        protocol: tcp
EOF
```
