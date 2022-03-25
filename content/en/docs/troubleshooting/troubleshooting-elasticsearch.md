---
title: "OpenSearch Scaling and Resizing"
linkTitle: "OpenSearch Scaling and Resizing"
description: "Scaling and resizing OpenSearch to restore healthy status"
weight: 1
draft: false
---

This document describes how to recover an OpenSearch cluster's health after it becomes unhealthy due to unassigned shards or disk pressure.

It also describes how to scale up the cluster's data nodes and increase the size of the volumes. Because the volume size change in the Verrazzano operator also affects the master nodes volume size, you must take additional steps to address the volume resizing of a StatefulSet.

First:
```
# Edit the Verrazzano operator
$ kubectl -n verrazzano-system edit deploy verrazzano-operator
```
Then, change the following portion by increasing the number of `ES_DATA_NODE_REPLICAS` to `3`, and the `ES_DATA_STORAGE` to `200Gi`:
```
- name: ES_DATA_NODE_REPLICAS
  value: "3"

- name: ES_DATA_STORAGE
  value: "200"
```
## Scaling OpenSearch data nodes

Follow this procedure to scale the OpenSearch data nodes.

1. Wait for the new data node pod to become ready and then check the health of the cluster:
   ```
   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health

   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
   ```
2. When you have a green state, replace the original data node `-0` pods:
   ```
   $ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=0
   $ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=0
   $ kubectl -n verrazzano-system delete pod/vmi-system-es-data-0-xxxxxxxxx-xxxx pvc/vmi-system-es-data-0
   $ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=1
   $ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=1
   ```
3. Wait for the new data node pod to become ready and then check the health of the cluster:
   ```
   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health

   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
   ```
4. When you have a green state, replace the original data node `-1` pods:
   ```
   $ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=0
   $ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=0
   $ kubectl -n verrazzano-system delete pod/vmi-system-es-data-1-xxxxxxxxx-xxxx pvc/vmi-system-es-data-1
   $ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=1
   $ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=1
   ```
5. Wait for the new data node pod to become ready and then check the health of the cluster:
   ```
   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health

   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
   ```
You should now have three data nodes that are healthy and at 200GB volumes.

## Address the master nodes' StatefulSet

Now to address the master nodes. Because you cannot directly change the size of the volume associated
with a volume template in a StatefulSet, you must follow this procedure:

1. First:
   ```
   $ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=0
   $ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=0
   $ kubectl -n verrazzano-system get sts vmi-system-es-master -o yaml > vmi-system-es-master.yaml
   ```
2. Edit the file created in the previous command, vmi-system-es-master.yaml

   a. Remove the lines starting with:
   ```
   creationTimestamp:
   generation:
   resourceVersion:
   selfLink:
   uid:
   status:
   ```
   b. Remove every line below status:

   c. Edit the section to increase the storage to the same value that you used for the Verrazzano operator:
   ```
   storage: 200Gi
   ```
   d. Save that file.

3. The following command will delete the StatefulSet, but allow the associated pods to continue to run.
   ```
   $ kubectl -n verrazzano-system delete sts vmi-system-es-master --cascade=orphan
   ```
4. Then run this command to recreate the StatefulSet with the new volume size defined:
   ```
   $ kubectl -n verrazzano-system apply -f vmi-system-es-master.yaml
   ```
5. The next steps are to delete the existing master node pods, one at a time, allowing the cluster to become healthy before moving on to the next node:
   ```
   $ kubectl -n verrazzano-system delete pod/vmi-system-es-master-0 pvc/elasticsearch-master-vmi-system-es-master-0
   ```
6. Wait for the new master node pod to become ready and then check the health of the cluster:
   ```
   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health

   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
   ```
7. When the cluster is healthy, continue to the next master node:
   ```
   $ kubectl -n verrazzano-system delete pod/vmi-system-es-master-1 pvc/elasticsearch-master-vmi-system-es-master-1
   ```
8. Wait for the new master node pod to become ready and then check the health of the cluster:
   ```
   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health

   $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
   ```
9. When the cluster is healthy, continue to the next master node:
   ```
   $ kubectl -n verrazzano-system delete pod/vmi-system-es-master-2 pvc/elasticsearch-master-vmi-system-es-master-2
   ```
10. Wait for the new master node pod to become ready and then check the health of the cluster:
    ```
    $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/health

    $ kubectl -n verrazzano-system exec -it vmi-system-es-master-0 -- curl http://127.0.0.1:9200/_cat/indices
    ```
11. When the cluster is healthy rescale the operators:
    ```
    $ kubectl -n verrazzano-system scale deploy verrazzano-operator --replicas=1
    $ kubectl -n verrazzano-system scale deploy verrazzano-monitoring-operator --replicas=1
    ```
This completes the process.
