---
title: "Restore Operation"
description: "Restore Component(s) to Verrazzano platform"
linkTitle: Restore Operation
weight: 1
draft: false
---

Verrazzano backup component `Velero` helps backup and migrate Kubernetes applications.
The restore operation allows you to restore all the objects and persistent volumes from a previously created backup.

### Prerequisites

Before proceeding the following information about object store should be provided as an input:

- Create an Oracle Cloud Object Storage bucket called velero in the root compartment of your Oracle Cloud tenancy.
  Refer to this [page](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm#usingconsole) for more information about creating a bucket with Object Storage.
- Object store prefix name. This will be a child folder under the bucket automatically created by the backup component.
- Object store region information.
- Verrazzano backup component requires object store to be Amazon S3 compatible. As a result you need to generate the signing key required to authenticate with Amazon S3.
  Follow these steps to create a [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#To4)
- There have been successful backups taken earlier.
- The restore can be done on a new Kubernetes cluster or an existing kubernetes cluster as well. 

### Prepare for Backup Or Restore

The following section assumes that the prerequisites have been met and the backup component is enabled.

You can now create the following objects as follows:

- Create a file `backup-secret.txt` having the object store credentials as shown below.

```backup-secret.txt
[default]
aws_access_key_id=<object store access key>
aws_secret_access_key=<object store secret key>
```

- Create a kubernetes secret `verrazzano-backup-creds` in the same namespace where the backup component is enabled. In this case the namespace is `velero`.
  The secret is consumed by the backup component `Velero` to back up objects to the object store.

```
kubectl create secret generic -n <backup-namespace> <secret-name> --from-file=<key>=<full_path_to_creds_file>

Example 
kubectl create secret generic -n velero verrazzano-backup-creds --from-file=cloud=backup-secret.txt
```

- Create a `BackupStorageLocation` which the backup component will reference for subsequent backups or restores. Below is an example of the `BackupStorageLocation`.
  Refer this [page](https://velero.io/docs/v1.8/api-types/backupstoragelocation/) for more information.

```yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: <backup location name>
  namespace: velero
spec:
  provider: aws
  objectStorage:
    bucket: <object store bucket name>
    prefix: <folder name>
  credential:
    name: <secret name created in previous step>
    key: <the key used in the secret>
  config:
    region: <object store region>
    s3ForcePathStyle: "true"
    s3Url: https://[objectstoragenamespace].compat.objectstorage.[region].oraclecloud.com
```


### Restoring a Component 

At this point you are ready to restore from an existing healthy back up.

We will focus on the component specific restore operations that we have already discussed in the backup section. 

Currently, the following components can be restored with hooks:
- MYSQL
- OpenSearch

**_NOTE:_**  Velero restore operation detects whether the component is already running and will skip object creation if objet already exists 


#### MYSQL Restore

For `MYSQL` Verrazzano offers a custom hook that can be used along with `Velero` to perform a restore successfully.

Delete the `keycloak` namespace to initiate a complete MYSQL restore

```shell
kubectl delete namespace keycloak
```

Below example of `Velero` restore [api](https://velero.io/docs/v1.8/api-types/restore/) object that can be invoked to perform a MYSQL restore.

```yaml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: <restore-name>
  namespace: velero
spec:
  backupName: <existing healthy backup name>
  includedNamespaces:
    - keycloak
  restorePVs: true
  hooks:
    resources:
      - name: <MYSQL restore resource name>
        includedNamespaces:
          - keycloak        
        labelSelector:
          matchLabels:
            app: mysql
        postHooks:
          - exec:
              container: mysql
              command:
                - bash
                - /etc/mysql/conf.d/mysql-hook.sh
                - -o restore
                - -f sunday.sql
              waitTimeout: 5m
              execTimeout: 5m
              onError: Fail

```

**_NOTE:_** The hook needs to be a `postHook` since we want to apply it after the Kubernetes objects are restored.

We can monitor the Velero restore object to understand the progress of our restore.

<details>
  <summary>MYSQL Restore Progress</summary>

```shell
velero restore get                                                           
NAME                   BACKUP              STATUS       STARTED                         COMPLETED   ERRORS   WARNINGS   CREATED                         SELECTOR
mysql-backup-restore   mysql-backup-test   InProgress   2022-07-07 17:00:33 -0700 PDT   <nil>       0        0          2022-07-07 17:00:33 -0700 PDT   <none>
```

</details>

<details>
  <summary>MYSQL Restore Object details</summary>

```shell
Name:         mysql-backup-restore
Namespace:    velero
Labels:       <none>
Annotations:  kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"velero.io/v1","kind":"Restore","metadata":{"annotations":{},"name":"mysql-backup-restore","namespace":"velero"},"spec":{"backupName":"nysql-backup-test","hooks":{"resources":[{"includedNamespaces":["keycloak"],"labelSelector":{"matchLabels":{"app":"mysql"}},"name":"verrazzano-sql-restore","postHooks":[{"exec":{"command":["bash","/etc/mysql/conf.d/mysql-hook.sh","-o restore","-f sunday.sql"],"container":"mysql","execTimeout":"5m","onError":"Fail","waitTimeout":"5m"}}]}]},"includedNamespaces":["keycloak"],"restorePVs":true}}


Phase:                       Completed
Total items to be restored:  40
Items restored:              40

Started:    2022-07-07 17:00:33 -0700 PDT
Completed:  2022-07-07 17:02:14 -0700 PDT

Backup:  nysql-backup-test

Namespaces:
  Included:  keycloak
  Excluded:  <none>

Resources:
  Included:        *
  Excluded:        nodes, events, events.events.k8s.io, backups.velero.io, restores.velero.io, resticrepositories.velero.io
  Cluster-scoped:  auto

Namespace mappings:  <none>

Label selector:  <none>

Restore PVs:  true

Restic Restores:
  Completed:
    keycloak/keycloak-0: istio-envoy, theme
    keycloak/mysql-5df654b5fd-8n4vv: data, istio-envoy

Preserve Service NodePorts:  auto
```

</details>

<details>
  <summary>POD Volume restore details</summary></summary>

```shell
kubectl get podvolumerestores -n velero                        
NAME                         NAMESPACE   POD                      VOLUME        STATUS      TOTALBYTES   BYTESDONE   AGE
mysql-backup-restore-44dmp   keycloak    mysql-5df654b5fd-8n4vv   istio-envoy   Completed   19913        19913       4m22s
mysql-backup-restore-l6vks   keycloak    keycloak-0               istio-envoy   Completed   20794        20794       4m22s
mysql-backup-restore-m447b   keycloak    keycloak-0               theme         Completed   104379       104379      4m22s
mysql-backup-restore-xv4qm   keycloak    mysql-5df654b5fd-8n4vv   data          Completed   219759281    219759281   4m22s
```
</details>


#### Opensearch Restore

For `OpenSearch` Verrazzano offers a custom hook that can be used along with `Velero` to perform a backup successfully.
Due to the nature of transient data handled by Opensearch, the hook invokes `Opensearch` snapshot apis to back up and restore data streams appropriately,
thereby ensuring there is no loss of data and avoids data corruption as well.

Delete existing Opensearch cluster running on the system and all related data. 

- Scale down `Verrazzano Monitoring Opeartor`

```shell
kubectl scale deploy -n verrazzano-system verrazzano-monitoring-operator --replicas=0
```

- Cleanup Opensearch components 

```shell
kubectl delete sts -n verrazzano-system vmi-system-es-master
kubectl delete deploy -n verrazzano-system vmi-system-es-data-0
kubectl delete deploy -n verrazzano-system vmi-system-es-data-1
kubectl delete deploy -n verrazzano-system vmi-system-es-data-2
kubectl delete deploy -n verrazzano-system vmi-system-es-ingest
kubectl delete pvc -n verrazzano-system vmi-system-es-data
kubectl delete pvc -n verrazzano-system vmi-system-es-data-1
kubectl delete pvc -n verrazzano-system vmi-system-es-data-2
```

Below example is `Velero` restore [api](https://velero.io/docs/v1.8/api-types/restore/) object that can be invoked to take an Opensearch restore.

```yaml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: <Opensearch restore name>
  namespace: velero
spec:
  backupName: <existing Opensearch backup name>
  includedNamespaces:
    - verrazzano-system
  labelSelector:
    matchLabels:
      verrazzano-component: opensearch
  restorePVs: false
  hooks:
    resources:
      - name: <Opensearch backup resource name>
        includedNamespaces:
          - verrazzano-system       
        labelSelector:
          matchLabels:            
            statefulset.kubernetes.io/pod-name: vmi-system-es-master-0
        postHooks:
          - exec:
              container: es-master
              command:
                - /usr/share/opensearch/bin/verrazzano-backup-hook
                - -operation
                - restore
                - -velero-backup-name
                - <existing Opensearch backup name>
              waitTimeout: 30m
              execTimeout: 30m
              onError: Fail

```

In case of Opensearch, during restore we perform the following actions:

- Recreate a new Opensearch cluster.  
- Use a `postHook` to invoke the Opensearch APIs that restores the snapshot data. That way we can get back the indices we had backed up prior to cleaning up. 

The restore logs are stored in the pod where the hook is executed and can be examined as shown below.

<details>
  <summary>Opensearch restore logs</summary></summary>

```shell
kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp//tmp/verrazzano-restore-hook-2357212430.log
{"level":"INFO","@timestamp":"2022-07-08T00:17:23.734Z","caller":"verrazzano-backup-hook/main.go:73","message":"Verrazzano backup and restore helper invoked."}
{"level":"INFO","@timestamp":"2022-07-08T00:17:23.734Z","caller":"opensearch/opensearch.go:123","message":"Checking if cluster is healthy"}
{"level":"INFO","@timestamp":"2022-07-08T00:17:23.734Z","caller":"opensearch/opensearch.go:80","message":"Checking if cluster is reachable"}
{"level":"ERROR","@timestamp":"2022-07-08T00:17:23.735Z","caller":"opensearch/opensearch.go:53","message":"HTTP 'GET' failure while invoking url 'http://127.0.0.1:9200' due to '{error 26 0  Get \"http://127.0.0.1:9200\": dial tcp 127.0.0.1:9200: connect: connection refused}'"}
{"level":"INFO","@timestamp":"2022-07-08T00:17:23.735Z","caller":"utilities/basicUtils.go:51","message":"Cluster is not reachable . Wait for '22' seconds ..."}
{"level":"ERROR","@timestamp":"2022-07-08T00:17:45.737Z","caller":"opensearch/opensearch.go:53","message":"HTTP 'GET' failure while invoking url 'http://127.0.0.1:9200' due to '{error 26 0  Get \"http://127.0.0.1:9200\": dial tcp 127.0.0.1:9200: connect: connection refused}'"}
{"level":"INFO","@timestamp":"2022-07-08T00:17:45.737Z","caller":"utilities/basicUtils.go:51","message":"Cluster is not reachable . Wait for '18' seconds ..."}
{"level":"INFO","@timestamp":"2022-07-08T00:18:03.795Z","caller":"opensearch/opensearch.go:116","message":"Cluster 'system' is reachable"}
{"level":"ERROR","@timestamp":"2022-07-08T00:18:33.803Z","caller":"opensearch/opensearch.go:65","message":"Error completing request, response code '503', response body '{\"error\":{\"root_cause\":[{\"type\":\"master_not_discovered_exception\",\"reason\":null}],\"type\":\"master_not_discovered_exception\",\"reason\":null},\"status\":503}'"}
{"level":"INFO","@timestamp":"2022-07-08T00:18:33.803Z","caller":"opensearch/opensearch.go:161","message":"Cluster health endpoint is reachable now"}
{"level":"ERROR","@timestamp":"2022-07-08T00:19:03.807Z","caller":"opensearch/opensearch.go:65","message":"Error completing request, response code '503', response body '{\"error\":{\"root_cause\":[{\"type\":\"master_not_discovered_exception\",\"reason\":null}],\"type\":\"master_not_discovered_exception\",\"reason\":null},\"status\":503}'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:03.807Z","caller":"utilities/basicUtils.go:51","message":"Cluster health is '' . Wait for '17' seconds ..."}
{"level":"INFO","@timestamp":"2022-07-08T00:19:20.811Z","caller":"opensearch/opensearch.go:201","message":"Cluster is reachable and healthy with status as 'green'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:21.954Z","caller":"verrazzano-backup-hook/main.go:130","message":"kubecontext retrieval successful"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:21.954Z","caller":"k8s/k8sHelper.go:32","message":"Populating connection data from backup 'opensearch-backup-test' in namespace 'velero'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:21.954Z","caller":"k8s/k8sHelper.go:129","message":"Fetching Velero backup 'opensearch-backup-test' in namespace 'velero'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:21.963Z","caller":"k8s/k8sHelper.go:44","message":"Detected Velero backup storage location 'verrazzano-backup-location' in namespace 'velero' used by backup 'opensearch-backup-test'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:21.963Z","caller":"k8s/k8sHelper.go:99","message":"Fetching Velero backup storage location 'verrazzano-backup-location' in namespace 'velero'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:21.999Z","caller":"k8s/k8sHelper.go:409","message":"Updating keystore in pod 'vmi-system-es-master-0'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:24.159Z","caller":"k8s/k8sHelper.go:409","message":"Updating keystore in pod 'vmi-system-es-master-1'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:26.290Z","caller":"k8s/k8sHelper.go:409","message":"Updating keystore in pod 'vmi-system-es-master-2'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:28.441Z","caller":"k8s/k8sHelper.go:430","message":"Updating keystore in pod 'vmi-system-es-data-0-6697998869-96cqt'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:30.571Z","caller":"k8s/k8sHelper.go:430","message":"Updating keystore in pod 'vmi-system-es-data-1-794b447c5f-q9ffp'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:32.941Z","caller":"k8s/k8sHelper.go:430","message":"Updating keystore in pod 'vmi-system-es-data-2-58df5c489-qktfb'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:35.384Z","caller":"opensearch/opensearch.go:223","message":"Secure settings reloaded sucessfully across all '7' nodes of the cluster"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:35.384Z","caller":"verrazzano-backup-hook/main.go:173","message":"Commencing OpenSearch restore .."}
{"level":"INFO","@timestamp":"2022-07-08T00:19:35.384Z","caller":"k8s/k8sHelper.go:161","message":"Scale deployment 'verrazzano-monitoring-operator' in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:35.391Z","caller":"k8s/k8sHelper.go:171","message":"Deployment scaling skipped as desired replicas is same as current replicas"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:35.391Z","caller":"k8s/k8sHelper.go:161","message":"Scale deployment 'vmi-system-es-ingest' in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:35.426Z","caller":"k8s/k8sHelper.go:206","message":"Scaling down pods ..."}
{"level":"INFO","@timestamp":"2022-07-08T00:19:35.427Z","caller":"k8s/k8sHelper.go:249","message":"Checking Pod 'vmi-system-es-ingest-8685b7f47-czjtt' status in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:35.458Z","caller":"utilities/basicUtils.go:51","message":"Pod 'vmi-system-es-ingest-8685b7f47-czjtt' is in 'Running' state . Wait for '22' seconds ..."}
{"level":"INFO","@timestamp":"2022-07-08T00:19:57.465Z","caller":"k8s/k8sHelper.go:214","message":"Successfully scaled deployment 'vmi-system-es-ingest' in namespace 'verrazzano-system' from '1' to '0' replicas "}
{"level":"INFO","@timestamp":"2022-07-08T00:19:57.465Z","caller":"opensearch/opensearch.go:459","message":"Start restore steps ...."}
{"level":"INFO","@timestamp":"2022-07-08T00:19:57.465Z","caller":"opensearch/opensearch.go:231","message":"Registering s3 backend repository 'verrazzano-backup'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:58.765Z","caller":"opensearch/opensearch.go:254","message":"Snapshot registered successfully !"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:58.765Z","caller":"opensearch/opensearch.go:331","message":"Deleting data streams followed by index .."}
{"level":"INFO","@timestamp":"2022-07-08T00:19:58.785Z","caller":"opensearch/opensearch.go:354","message":"Data streams and data indexes deleted successfully !"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:58.785Z","caller":"opensearch/opensearch.go:360","message":"Triggering restore with name 'opensearch-backup-test'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:59.118Z","caller":"opensearch/opensearch.go:372","message":"Snapshot restore triggered successfully !"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:59.118Z","caller":"opensearch/opensearch.go:378","message":"Checking restore progress with name 'opensearch-backup-test'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:59.123Z","caller":"opensearch/opensearch.go:403","message":"Data stream 'verrazzano-application-velero' restore status 'YELLOW'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:59.123Z","caller":"opensearch/opensearch.go:403","message":"Data stream 'verrazzano-system' restore status 'YELLOW'"}
{"level":"INFO","@timestamp":"2022-07-08T00:19:59.123Z","caller":"utilities/basicUtils.go:51","message":"Restore is in progress . Wait for '21' seconds ..."}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.127Z","caller":"opensearch/opensearch.go:403","message":"Data stream 'verrazzano-application-velero' restore status 'GREEN'"}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.127Z","caller":"opensearch/opensearch.go:406","message":"Data stream 'verrazzano-application-velero' restore complete"}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.127Z","caller":"opensearch/opensearch.go:403","message":"Data stream 'verrazzano-system' restore status 'GREEN'"}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.127Z","caller":"opensearch/opensearch.go:406","message":"Data stream 'verrazzano-system' restore complete"}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.127Z","caller":"opensearch/opensearch.go:432","message":"All streams are healthy"}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.127Z","caller":"k8s/k8sHelper.go:221","message":"Checking deployment with labelselector 'verrazzano-component=kibana' exists in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.141Z","caller":"k8s/k8sHelper.go:161","message":"Scale deployment 'vmi-system-kibana' in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.171Z","caller":"k8s/k8sHelper.go:206","message":"Scaling down pods ..."}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.171Z","caller":"k8s/k8sHelper.go:249","message":"Checking Pod 'vmi-system-kibana-7d66ddbd89-msjvb' status in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:20:20.183Z","caller":"utilities/basicUtils.go:51","message":"Pod 'vmi-system-kibana-7d66ddbd89-msjvb' is in 'Running' state . Wait for '17' seconds ..."}
{"level":"INFO","@timestamp":"2022-07-08T00:20:37.195Z","caller":"k8s/k8sHelper.go:214","message":"Successfully scaled deployment 'vmi-system-kibana' in namespace 'verrazzano-system' from '1' to '0' replicas "}
{"level":"INFO","@timestamp":"2022-07-08T00:20:37.196Z","caller":"k8s/k8sHelper.go:161","message":"Scale deployment 'verrazzano-monitoring-operator' in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:20:37.225Z","caller":"utilities/basicUtils.go:51","message":"Wait for pods to come up . Wait for '15' seconds ..."}
{"level":"INFO","@timestamp":"2022-07-08T00:20:52.227Z","caller":"k8s/k8sHelper.go:214","message":"Successfully scaled deployment 'verrazzano-monitoring-operator' in namespace 'verrazzano-system' from '0' to '1' replicas "}
{"level":"INFO","@timestamp":"2022-07-08T00:20:52.227Z","caller":"utilities/basicUtils.go:51","message":"Waiting for Verrazzano Monitoring Operator to come up . Wait for '20' seconds ..."}
{"level":"INFO","@timestamp":"2022-07-08T00:21:12.230Z","caller":"k8s/k8sHelper.go:330","message":"Checking pods with labelselector 'app=system-es-ingest' in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:21:12.246Z","caller":"k8s/k8sHelper.go:343","message":"Checking pods with labelselector 'app=system-kibana' in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:21:12.246Z","caller":"k8s/k8sHelper.go:249","message":"Checking Pod 'vmi-system-es-ingest-8685b7f47-jkzgm' status in namespace 'verrazzano-system"}
{"level":"INFO","@timestamp":"2022-07-08T00:21:12.259Z","caller":"k8s/k8sHelper.go:283","message":"Pod 'vmi-system-es-ingest-8685b7f47-jkzgm' is in 'Running' state"}
{"level":"INFO","@timestamp":"2022-07-08T00:21:12.259Z","caller":"k8s/k8sHelper.go:239","message":"Pod 'vmi-system-es-ingest-8685b7f47-jkzgm' in namespace 'verrazzano-system' is now in 'Ready' state"}
{"level":"INFO","@timestamp":"2022-07-08T00:21:12.259Z","caller":"verrazzano-backup-hook/main.go:212","message":"OPENSEARCH restore was successfull"}
```
</details>


They are also available as part of the Velero restore logs.  







