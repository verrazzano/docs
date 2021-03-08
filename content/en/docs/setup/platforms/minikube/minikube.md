---
title: minikube
description: Instructions for setting up a minikube cluster for Verrazzano
linkTitle: minikube
Weight: 8
draft: false
---

[minikube](https://minikube.sigs.k8s.io/docs/) quickly sets up a local Kubernetes cluster on macOS, Linux, and Windows. Follow
these instructions to prepare a minikube cluster for running Verrazzano.

## Prerequisites

- Install [minikube](https://minikube.sigs.k8s.io/docs/start/).
- Install a [driver](https://minikube.sigs.k8s.io/docs/drivers/) (on macOS or Windows, select a VM-based driver, not Docker).

## Prepare the minikube cluster

To prepare the minikube cluster for use with Verrazzano, you must create the cluster and then expose services
of type `LoadBalancer` by using the `minikube tunnel` command.

### Create the minikube cluster

Create a minikube cluster using a supported Kubernetes version and appropriate driver.  On Linux hosts, the default
driver is acceptable; on macOS, hyperkit is recommended.

```shell
$ minikube start \
    --kubernetes-version=v1.18.8 \
    --driver=hyperkit \
    --memory=16384 \
    --cpus=4 \
    --extra-config=apiserver.service-account-signing-key-file=/var/lib/minikube/certs/sa.key \
    --extra-config=apiserver.service-account-issuer=kubernetes/serviceaccount \
    --extra-config=apiserver.service-account-api-audiences=api
```

### Run `minikube tunnel`

minikube exposes Kubernetes services of type [`LoadBalancer`](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/) with the
[`minikube tunnel`](https://minikube.sigs.k8s.io/docs/commands/tunnel/) command.  Run a tunnel in a separate terminal from minikube:

```shell
$ minikube tunnel
```
### Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).
