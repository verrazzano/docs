---
title: KIND
description: Instructions for setting up a KIND cluster for Verrazzano
linkTitle: KIND
Weight: 8
draft: false
---

### Prepare for the KIND install


Create the KIND cluster.

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

#### Image caching to speed up install

If you are experimenting with Verrazzano and expect that you may need to delete the KIND cluster and later, install Verrazzano again on a new KIND cluster, then you can follow these steps to ensure that the image cache used by containerd inside KIND is preserved across clusters. Subsequent installs will be faster than the first install, because they will not need to pull the images again.

1\. Create a named Docker volume that will be used for the image cache, and note its `Mountpoint` path. In this example, the volume is named `containerd`.  

```shell
docker volume create containerd

docker volume inspect containerd #Sample output is shown

{
    "CreatedAt": "2021-01-11T16:27:47Z",
    "Driver": "local",
    "Labels": {},
    "Mountpoint": "/var/lib/docker/volumes/containerd/_data",
    "Name": "containerd",
    "Options": {},
    "Scope": "local"
}
```

2\. Specify the `Mountpoint` path obtained, as the `hostPath` under `extraMounts` in your KIND configuration file, with a `containerPath` of `/var/lib/containerd`, which is the default containerd image caching location inside the KIND container. An example of the modified KIND configuration is shown in the following `create cluster` command:

```shell
kind create cluster --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
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
    extraMounts:
      - hostPath: /var/lib/docker/volumes/containerd/_data
        containerPath: /var/lib/containerd #This is the location of the image cache inside the KIND container
EOF
```
