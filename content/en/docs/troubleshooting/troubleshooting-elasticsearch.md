---
title: "Elasticsearch Scaling and Resizing"
linkTitle: "Elasticsearch Scaling and Resizing"
description: "Scaling and Resizing Elasticsearch to restore healthy status"
weight: 1
draft: false
---

This document describes how to recover an Elasticsearch cluster's health after it becomes unhealthy due to unassigned shards or disk pressure.

This document describes how to scale up the cluster's data nodes and increase the size of the volumes. Being that the volume size change in the Verrazzano Operator also effects the master nodes volume size, additional steps must be taken to address the volume resizing of a StatefulSet.
```
# Edit the Verrazzano Operator
$ kubectl -n verrazzano-system edit deploy verrazzano-operator
```
Change the following portion by increasing the number of ES_DATA_NODE_REPLICAS to 3, and the ES_DATA_STORAGE to 200Gi:
```
- name: ES_DATA_NODE_REPLICAS
  value: "3"

- name: ES_DATA_STORAGE
  value: "200"
```
**Scaling Elasticsearch Data Nodes**

Wait for the new data node pod to become ready and check the health of the cluster:
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health
```
and
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
```
When you have a green state, replace the original data node -0 pods:
```
$ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=0
$ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=0
$ kubectl -n verrazzano-system delete pod/vmi-system-es-data-0-xxxxxxxxx-xxxx pvc/vmi-system-es-data-0
$ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=1
$ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=1
```
Wait for the new data node pod to become ready and check the health of the cluster:
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health
```
and
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
```
When you have a green state, replace the original data node -1 pods:
```
$ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=0
$ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=0
$ kubectl -n verrazzano-system delete pod/vmi-system-es-data-1-xxxxxxxxx-xxxx pvc/vmi-system-es-data-1
$ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=1
$ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=1
```
Wait for the new data node pod to become ready and check the health of the cluster:
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health
```
and
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
```
You should now have 3 data nodes that are healthy and at 200GB volumes.

**Addressing the master nodes' Statefulset**

Now to address the master nodes. Because you cannot directly change the size of the volume associated
with a volume template in a Statefulset, you must follow this procedure:
```
$ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=0
$ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=0
$ kubectl -n verrazzano-system get sts vmi-system-es-master -o yaml > vmi-system-es-master.yaml
```
Edit the file created in the previous command, vmi-system-es-master.yaml

remove the lines starting with:
```
creationTimestamp:
generation:
resourceVersion:
selfLink:
uid:
status:
```
and every line below status:

edit the section like below to increase the storage to the same value as you did in the Verrazzano Operator:
```
storage: 200Gi
```
Save that file.

The following command will delete the Statefulset, but allow the associated pods to continue to run.
```
$ kubectl -n verrazzano-system delete sts vmi-system-es-master --cascade=orphan
```
then run this command will re-create the Statefulset with the new volume size defined:
```
$ kubectl -n verrazzano-system apply -f vmi-system-es-master.yaml
```
The next steps are to one at a time, delete the existing master node pods, allowing the cluster to become healthy before moving on to the next node:
```
$ kubectl -n verrazzano-system delete pod/vmi-system-es-master-0 pvc/elasticsearch-master-vmi-system-es-master-0
```
Wait for the new master node pod to become ready and check the health of the cluster:
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health
```
and
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
```
When the cluster is healthy, continue to the next master node:
```
$ kubectl -n verrazzano-system delete pod/vmi-system-es-master-1 pvc/elasticsearch-master-vmi-system-es-master-1
```
Wait for the new master node pod to become ready and check the health of the cluster:
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health
```
and
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
```
When the cluster is healthy, continue to the next master node:
```
$ kubectl -n verrazzano-system delete pod/vmi-system-es-master-2 pvc/elasticsearch-master-vmi-system-es-master-2
```
Wait for the new master node pod to become ready and check the health of the cluster:
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health
```
and
```
$ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
```
When the cluster is healthy rescale the operators:
```
$ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=1
$ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=1
```
This completes the process.