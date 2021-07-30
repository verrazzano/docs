---
title: "Customize Elasticsearch"
description: "Customize Elasticsearch with Verrazzano"
linkTitle: Elasticsearch
weight: 8
draft: false
---

Verrazzano supports two general cluster topologies for an Elasticsearch cluster:
1. A single-node cluster (master/ingest/data roles performed by a single node).
2. A multi-node cluster configuration with separate master, data, and ingest nodes.

[Installation Profiles](/docs/setup/install/profiles/) describes the default Elasticsearch cluster
configurations provided by Verrazzano.  

You can customize the node characteristics of your Elasticsearch cluster through the
[spec.components.elasticsearch.installArgs](/docs/reference/api/verrazzano/verrazzano/#elasticsearch-component)
field in the Verrazzano custom resource.  When installing Verrazzano, you can use this field to specify a list of Helm 
value overrides for the Elasticsearch configuration.

These Helm overrides let you to customize the following node characteristics:
* Number of node replicas.
* Memory request size per node.
* Storage request size (data nodes only).

The following table lists the Helm values in the Verrazzano system chart related to Elasticsearch nodes:

| Name | Description
| ------------- |:-------------
| `nodes.master.replicas` | Number of master node replicas.
| `nodes.master.requests.memory` | Memory request amount expressed as a [Quantity](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/#Quantity).
| `nodes.ingest.replicas` | Number of ingest node replicas.
| `nodes.ingest.requests.memory` | Memory request amount expressed as a [Quantity](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/#Quantity).
| `nodes.data.replicas` | Number of data node replicas.
| `nodes.data.requests.memory` | Memory request amount expressed as a [Quantity](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/#Quantity).
| `nodes.data.requests.storage` | Storage request amount expressed as a [Quantity](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/#Quantity).

The following example overrides the `dev` installation profile Elasticsearch configuration (a single-node cluster with
1Gi of memory and ephemeral storage) to use a multi-node cluster with persistent storage:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-es-example
spec:
  profile: dev
  components:
    elasticsearch:
      installArgs:
      - name: nodes.master.replicas
        value: "1"
      - name: nodes.master.requests.memory
        value: "1G"
      - name: nodes.ingest.replicas
        value: "1"
      - name: nodes.ingest.requests.memory
        value: "1G"
      - name: nodes.data.replicas
        value: "3"
      - name: nodes.data.requests.memory
        value: "1.5G"
      - name: nodes.data.requests.storage
        value: "10Gi"
```

Listing the pods and persistent volumes in the `verrazzano-system` namespace for the previous configuration 
shows the expected nodes are running with the appropriate data volumes:

```
$ kubectl  get pvc,pod -n verrazzano-system 
NAME                                                                STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
persistentvolumeclaim/elasticsearch-master-vmi-system-es-master-0   Bound    pvc-8ffff457-4d72-4a72-89ba-2cdcb8eade38   10Gi       RWO            standard       6m51s
persistentvolumeclaim/vmi-system-es-data                            Bound    pvc-e32c2182-46ba-4789-b577-195874b3dd69   10Gi       RWO            standard       6m53s
persistentvolumeclaim/vmi-system-es-data-1                          Bound    pvc-67789196-d688-4d06-b074-77655a913552   10Gi       RWO            standard       6m53s
persistentvolumeclaim/vmi-system-es-data-2                          Bound    pvc-43e07e3e-0713-4ab1-ac3f-812069c35cbb   10Gi       RWO            standard       6m53s

NAME                                                   READY   STATUS    RESTARTS   AGE
pod/coherence-operator-6986d6cf95-6b58p                1/1     Running   2          7m3s
pod/fluentd-fn28c                                      2/2     Running   2          7m12s
pod/oam-kubernetes-runtime-679c6f6775-79tvm            1/1     Running   0          5m11s
pod/verrazzano-api-58c5f65c8-6zbpc                     2/2     Running   0          7m12s
pod/verrazzano-application-operator-5766b899fd-9fjhb   1/1     Running   0          4m55s
pod/verrazzano-console-6599854544-pw56c                2/2     Running   0          7m12s
pod/verrazzano-monitoring-operator-55877766d4-9ktvh    1/1     Running   0          7m12s
pod/verrazzano-operator-75b5cd49fc-68cm4               1/1     Running   0          7m12s
pod/vmi-system-es-data-0-5884cfb84d-hn8xg              2/2     Running   0          6m52s
pod/vmi-system-es-data-1-679775494f-pdwzf              2/2     Running   0          6m52s
pod/vmi-system-es-data-2-5886d745c5-6pscm              2/2     Running   0          6m52s
pod/vmi-system-es-ingest-795749ddd8-cs4pc              3/3     Running   0          6m52s
pod/vmi-system-es-master-0                             2/2     Running   0          6m51s
pod/vmi-system-grafana-b94fcbb67-ktwf8                 3/3     Running   0          6m52s
pod/vmi-system-kibana-6594cfccc-j8gp5                  3/3     Running   0          6m51s
pod/vmi-system-prometheus-0-75864fc668-s5xv8           4/4     Running   0          44s
pod/weblogic-operator-5bd7bb6fb5-wz5cr                 2/2     Running   0          6m30s
```

Note that the `master` node uses the same amount of persistent storage as is configured for the data nodes.

Running the command `kubectl describe pod -n verrazzano-system vmi-system-es-data-0-5884cfb84d-hn8xg` shows the 
requested amount of memory:

```
Containers:
  es-data:
    Container ID:  containerd://cc01f24b107da0e1e90a05a49c7fd969761f59a81316fa01f7cc56a166684628
    Image:         ghcr.io/verrazzano/elasticsearch:7.6.1-20201130145440-5c76ab1
    Image ID:      ghcr.io/verrazzano/elasticsearch@sha256:3d2cbb539f9ebba991c6f36db4fbaa9dc9c03e6192a28787869f7850cc2bd66c
    Ports:         9200/TCP, 9300/TCP
    Host Ports:    0/TCP, 0/TCP
    Args:
      elasticsearch
      -E
      logger.org.elasticsearch=INFO
    State:          Running
      Started:      Thu, 29 Jul 2021 06:04:17 +0000
    Ready:          True
    Restart Count:  0
    Requests:
      memory:   1500M
```
