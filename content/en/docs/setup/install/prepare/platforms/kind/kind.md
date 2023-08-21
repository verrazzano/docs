---

title: Prepare a kind Cluster
description: Set up a kind cluster for Verrazzano
Weight: 4
draft: false
aliases:
  - /docs/setup/platforms/kind/kind
---

[kind](https://kind.sigs.k8s.io/) is a tool for running local Kubernetes clusters using Docker container “nodes”.  Follow
these instructions to prepare a kind cluster for running Verrazzano.

{{% alert title="NOTE" color="primary" %}}
kind is not recommended for use on macOS and Windows because the Docker network is not directly exposed
to the host.
{{% /alert %}}

## Prerequisites

- Install [Docker](https://docs.docker.com/install/)
- Install [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)

## Prepare the kind cluster

To prepare the kind cluster for use with Verrazzano, you must create the cluster and then install and configure
[MetalLB](https://metallb.universe.tf/) in that cluster.

You can create the kind cluster in two ways: with or without image caching; image caching can speed up your
installation time.

### Create a kind cluster

kind images are prebuilt for each release.  To find images suitable for a given release, check the
[release notes](https://github.com/kubernetes-sigs/kind/releases) for your kind version (check with `kind version`).
There you'll find a complete listing of images created for a kind release.

The following example references a Kubernetes v1.26-based image built for kind v0.20.0.  Replace that image
with one suitable for the kind release you are using. For the supported Kubernetes versions, see the listing [here]({{< relref "/docs/setup/install/prepare/prereqs#kubernetes" >}}).
{{< clipboard >}}
<div class="highlight">

    $ kind create cluster --config - <<EOF
    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    nodes:
      - role: control-plane
        image: kindest/node:v1.26@sha256:69860bda5563ac81e3c0057d654b5253219618a22ec3a346306239bba8cfa1a6
        kubeadmConfigPatches:
          - |
            kind: ClusterConfiguration
            apiServer:
              extraArgs:
                "service-account-issuer": "kubernetes.default.svc"
                "service-account-signing-key-file": "/etc/kubernetes/pki/sa.key"
    EOF

</div>
{{< /clipboard >}}

### Create a kind cluster with image caching

While developing or experimenting with Verrazzano, you might destroy and re-create your kind cluster multiple
times.  To speed up Verrazzano installation, follow these steps to ensure that the image cache used by
containerd inside a kind cluster, is preserved across clusters. Subsequent installations will be faster
because they will not need to pull the images again.

1\. Create a named Docker volume that will be used for the image cache and note its `mountPoint` path. In this example, the volume is named `containerd`.
{{< clipboard >}}
<div class="highlight">

    $ docker volume create containerd

    $ docker volume inspect containerd

    # Sample output
    {
        "CreatedAt": "2021-01-11T16:27:47Z",
        "Driver": "local",
        "Labels": {},
        "Mountpoint": "/var/lib/docker/volumes/containerd/_data",
        "Name": "containerd",
        "Options": {},
        "Scope": "local"
    }

</div>
{{< /clipboard >}}

2\. Specify the `mountPoint` path obtained, as the `hostPath` under `extraMounts` in your kind configuration file, with a `containerPath` of `/var/lib/containerd`, which is the default containerd image caching location inside the kind container. An example of the modified kind configuration is shown in the following `create cluster` command.
{{< clipboard >}}
<div class="highlight">

    $ kind create cluster --config - <<EOF
    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    nodes:
      - role: control-plane
        image: kindest/node:v1.26@sha256:69860bda5563ac81e3c0057d654b5253219618a22ec3a346306239bba8cfa1a6
        kubeadmConfigPatches:
          - |
            kind: ClusterConfiguration
            apiServer:
              extraArgs:
                "service-account-issuer": "kubernetes.default.svc"
                "service-account-signing-key-file": "/etc/kubernetes/pki/sa.key"
        extraMounts:
          - hostPath: /var/lib/docker/volumes/containerd/_data
            containerPath: /var/lib/containerd #This is the location of the image cache inside the kind container
    EOF

</div>
{{< /clipboard >}}

**NOTE**: When using a private container registry or experiencing rate-limiting of container image pulls, refer to the [kind documentation](https://kind.sigs.k8s.io/docs/user/private-registries/).

## Install and configure MetalLB

By default, kind does not provide an implementation of network load balancers ([Services of type LoadBalancer](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/)).
[MetalLB](https://metallb.universe.tf/) offers a network load balancer implementation.

To install MetalLB:
{{< clipboard >}}
<div class="highlight">

    $ kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.11.0/manifests/namespace.yaml
    $ kubectl create secret generic \
        -n metallb-system memberlist \
        --from-literal=secretkey="$(openssl rand -base64 128)"
    $ kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.11.0/manifests/metallb.yaml

</div>
{{< /clipboard >}}

**NOTE**: When using MetalLB on Kubernetes v1.26, install MetalLB v0.11.0, which you can do with manifest files or a Helm chart.

Wait for MetalLB to be ready, as shown:
{{< clipboard >}}
<div class="highlight">

    $ kubectl get pods -n metallb-system -L app=metallb
    NAME                         READY   STATUS    RESTARTS       AGE   APP=METALLB
    controller-d9d8c78b6-hhplg   1/1     Running   1 (3d4h ago)   9d    
    speaker-4lqpg                1/1     Running   1 (3d4h ago)   9d

</div>
{{< /clipboard >}}

For further details, see the MetalLB [installation guide](https://metallb.universe.tf/installation/#installation-by-manifest).

MetalLB is idle until configured.  Configure MetalLB in Layer 2 mode and give it control over a range of IP addresses in the `kind` Docker network.
In versions v0.7.0 and earlier, kind uses Docker's default bridge network; in versions v0.8.0 and later, it creates its own bridge network in kind.

To determine the subnet of the `kind` Docker network in kind v0.8.0 and later:
{{< clipboard >}}
<div class="highlight">

    $ docker inspect kind | jq '.[0].IPAM.Config[0].Subnet' -r

    # Sample output
    172.18.0.0/16

</div>
{{< /clipboard >}}

To determine the subnet of the `kind` Docker network in kind v0.7.0 and earlier:
{{< clipboard >}}
<div class="highlight">

    $ docker inspect bridge | jq '.[0].IPAM.Config[0].Subnet' -r

    # Sample output
    172.17.0.0/16

</div>
{{< /clipboard >}}


For use by MetalLB, assign a range of IP addresses at the end of the `kind` network's subnet CIDR range.

{{< clipboard >}}
<div class="highlight">

    $ kubectl apply -f - <<-EOF
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

</div>
{{< /clipboard >}}

## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install" >}}).
