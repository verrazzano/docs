---
title: minikube
description: 
linkTitle: minikube
Weight: 3
draft: true
aliases:
  - /docs/setup/platforms/minikube/minikube
---

[minikube](https://minikube.sigs.k8s.io/docs/) quickly sets up a local Kubernetes cluster on macOS, Linux, and Windows. Follow
these instructions to prepare a minikube cluster for running Verrazzano.

## Prerequisites

- Install [minikube](https://minikube.sigs.k8s.io/docs/start/).
- Install a [driver](https://minikube.sigs.k8s.io/docs/drivers/):
  - On macOS or Windows, select a VM-based driver, not Docker.
  - Oracle Linux 7, deploying WebLogic or Coherence applications requires the kvm2 driver because the Docker driver [requires a kernel patch](https://github.com/kubernetes/kubernetes/issues/72878).


## Prepare the minikube cluster

To prepare the minikube cluster for use with Verrazzano, you must create the cluster and then expose services
of type `LoadBalancer` by using the `minikube tunnel` command.

### Create the minikube cluster

Create a minikube cluster using a supported Kubernetes version and appropriate driver.  On Linux hosts, the default
driver is acceptable; on macOS, hyperkit is recommended.
{{< clipboard >}}
<div class="highlight">

    $ minikube start \
        --kubernetes-version=v1.18.8 \
        --driver=hyperkit \
        --memory=16G \
        --disk-size=30G \
        --cpus=4 \
        --extra-config=apiserver.service-account-signing-key-file=/var/lib/minikube/certs/sa.key \
        --extra-config=apiserver.service-account-issuer=kubernetes/serviceaccount \
        --extra-config=apiserver.service-account-api-audiences=api

</div>
{{< /clipboard >}}

### Run `minikube tunnel`

minikube exposes Kubernetes services of type [`LoadBalancer`](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/) with the
[`minikube tunnel`](https://minikube.sigs.k8s.io/docs/commands/tunnel/) command.  

Note that the `ip` command is required by `minikube tunnel`.  You may need to add `/sbin` to your `PATH` environment variable.  

Run a tunnel in a separate terminal from minikube:

{{< clipboard >}}
<div class="highlight">

```
$ minikube tunnel
```
</div>
{{< /clipboard >}}
## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).
