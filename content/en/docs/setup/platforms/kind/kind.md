---
title: KIND
description: Instructions for setting up a KIND cluster for Verrazzano
linkTitle: KIND
Weight: 8
draft: false
---

[kind](https://kind.sigs.k8s.io/) is a tool for running local Kubernetes clusters using Docker container “nodes”.  Follow
these instructions to prepare a kind cluster for running Verrazzano.

{{% alert title="NOTE" color="warning" %}}
KIND is not recommended for use on macOS and Windows due to the fact that the Docker network is not directly exposed
to the host.
{{% /alert %}}

## Pre-requisites

- Install [Docker](https://docs.docker.com/install/)
- Install [KIND](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) v0.8.0 or later

## Prepare the KIND cluster


### Create KIND cluster

Prebuilt KIND images are built for each release.  To find images suitable for a given release you should check the
[release notes](https://github.com/kubernetes-sigs/kind/releases) for your given kind version (check with `kind version`)
where you'll find a complete listing of images created for a kind release.

The example below references a Kubernetes 1.18.8 based image built for KIND v0.9.0.  Replace that image
with one suitable for the kind release you are using.

```shell
kind create cluster --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.18.8@sha256:f4bcc97a0ad6e7abaf3f643d890add7efe6ee4ab90baeb374b4f41a4c95567eb
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            "service-account-issuer": "kubernetes.default.svc"
            "service-account-signing-key-file": "/etc/kubernetes/pki/sa.key"
EOF
```

### Install and configure MetalLB

By default, KIND does not provide an implementation of network load-balancers ([Services of type LoadBalancer](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/)).
[MetalLB](https://metallb.universe.tf/)  offers a Network load-balancer implementation.  Follow these steps to install MetalLB.

```shell
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.5/manifests/namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.9.5/manifests/metallb.yaml
kubectl create secret generic -n metallb-system memberlist --from-literal=secretkey="$(openssl rand -base64 128)"
```

For further details, see the MetalLB [installation guide](https://metallb.universe.tf/installation/#installation-by-manifest).

MetalLB is idle until configured.  Configure MetalLB in Layer 2 mode and give it control over a range of IP addresses in the `kind` Docker network.
To determine the subnet of the `kind` docker network, execute the following:

```shell
> docker inspect kind | jq '.[0].IPAM.Config[0].Subnet' -r
172.18.0.0/16
```

Assign a range of IP addresses at the end of the `kind` network's subnet CIDR range for use by MetalLB.

```shell
kubectl apply -f - <<-EOF
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: my-ip-space
      protocol: layer2
      addresses:
      - 172.18.0.230-172.18.0.250
EOF
```

## Image caching to speed up install

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
    image: kindest/node:v1.18.8@sha256:f4bcc97a0ad6e7abaf3f643d890add7efe6ee4ab90baeb374b4f41a4c95567eb
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            "service-account-issuer": "kubernetes.default.svc"
            "service-account-signing-key-file": "/etc/kubernetes/pki/sa.key"
    extraMounts:
      - hostPath: /var/lib/docker/volumes/containerd/_data
        containerPath: /var/lib/containerd #This is the location of the image cache inside the KIND container
EOF
```
