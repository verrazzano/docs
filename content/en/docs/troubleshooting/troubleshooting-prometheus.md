---
title: "Prometheus"
linkTitle: "Prometheus"
description: "Troubleshoot Prometheus issues"
weight: 1
draft: false
---

### Kubernetes cluster monitors are in a "DOWN" state
When viewing targets in the Prometheus console some Kubernetes cluster monitors may be down (`kube-etcd`, `kube-proxy`, etc.) This is likely caused by the configuration of the Kubernetes cluster
itself. Depending on the type of cluster certain metrics may be disabled by default. Enabling metrics is cluster dependent so refer to the documentation for your cluster type for details.

For example, to enable `kube-proxy` metrics on KinD clusters, edit the `kube-proxy` configmap:
```
$ kubectl edit cm/kube-proxy -n kube-system
```
Replace the `metricsBindAddress` value with the following and save the configmap:
```
metricsBindAddress: 0.0.0.0:10249
```
Then restart the `kube-proxy` pods:
```
$ kubectl delete pod -l k8s-app=kube-proxy -n kube-system
```

See this GitHub [issue](https://github.com/prometheus-community/helm-charts/issues/204) for additional information.
