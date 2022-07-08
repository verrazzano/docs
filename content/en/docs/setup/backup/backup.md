---
title: "Backup Operation"
description: "Backup component(s) on Verrazzano platform"
linkTitle: Backup Operation
weight: 1
draft: false
---

Verrazzano backup component `Velero` helps backup and migrate Kubernetes applications. 
Here are the steps to use [Oracle Cloud Object Storage](https://docs.oracle.com/en-us/iaas/Content/Object/Concepts/objectstorageoverview.htm) as a destination for Verrazzano backups.

### Prerequisites 

Before proceeding the following information about object store should be provided as an input: 

- Create an Oracle Cloud Object Storage bucket called velero in the root compartment of your Oracle Cloud tenancy. 
  Refer to this [page](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm#usingconsole) for more information about creating a bucket with Object Storage. 
- Object store prefix name. This will be a child folder under the bucket automatically created by the backup component.
- Object store region information.  
- Verrazzano backup component requires object store to be Amazon S3 compatible. As a result you need to generate the signing key required to authenticate with Amazon S3.
  Follow these steps to create a [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#To4) 

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

- Create a `BackupStorageLocation` which the backup component will reference for subsequent backups. Below is an example of the `BackupStorageLocation`. 
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


### Taking a Backup 

At this point you are ready to back up a namespace or a component with Velero. 

For certain components Verrazzano offers specialized `hooks` to ensure backup which can be used in conjunction with Velero as outline [here](https://velero.io/docs/v1.8/backup-hooks/).   

Currently, the following components can be backed up with hooks:
- MYSQL
- OpenSearch 

We will now take a look on how to take a component specific backup. 

#### MYSQL Backup 

For `MYSQL` Verrazzano offers a custom hook that can be used along with `Velero` to perform a backup successfully. 

Below example is a sample `Velero` backup [api](https://velero.io/docs/v1.8/api-types/backup/) object that can be invoked to take a MYSQL backup. 

```yaml
apiVersion: velero.io/v1
kind: Backup
metadata:
  name: <backup name>
  namespace: velero
spec:
  includedNamespaces:
  - keycloak
  defaultVolumesToRestic: true
  storageLocation: <backup storage location as referenced in prerequisites>
  hooks:
    resources:
      -
        name: <MYSQL backup resource name>
        includedNamespaces:
          - keycloak       
        labelSelector:
          matchLabels:
            app: mysql
        pre:
          -
            exec:
              container: mysql
              command:
                - bash
                - /etc/mysql/conf.d/mysql-hook.sh
                - -o backup
                - -f <mysql-dump-filename.sql>
              onError: Fail
              timeout: 5m
```

We can monitor the Velero backup object to understand the progress of our backup. 

<details>
  <summary>MYSQL Backup Progress</summary>

```shell
velero backup get                                                                     
NAME                STATUS       ERRORS   WARNINGS   CREATED                         EXPIRES   STORAGE LOCATION             SELECTOR
mysql-backup-test   InProgress   0        0          2022-07-07 14:56:32 -0700 PDT   29d       verrazzano-backup-location   <none>
```

</details>

<details>
  <summary>MYSQL Backup Object details</summary>

```shell
Name:         mysql-backup-test
Namespace:    velero
Labels:       velero.io/storage-location=verrazzano-backup-location
Annotations:  kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"velero.io/v1","kind":"Backup","metadata":{"annotations":{},"name":"mysql-backup-test","namespace":"velero"},"spec":{"defaultVolumesToRestic":true,"hooks":{"resources":[{"includedNamespaces":["keycloak"],"labelSelector":{"matchLabels":{"app":"mysql"}},"name":"verrazzano-sql-backup","pre":[{"exec":{"command":["bash","/etc/mysql/conf.d/mysql-hook.sh","-o backup","-f sunday.sql"],"container":"mysql","onError":"Fail","timeout":"5m"}}]}]},"includedNamespaces":["keycloak"],"storageLocation":"verrazzano-backup-location"}}

  velero.io/source-cluster-k8s-gitversion=v1.22.5
  velero.io/source-cluster-k8s-major-version=1
  velero.io/source-cluster-k8s-minor-version=22

Phase:  Completed

Errors:    0
Warnings:  0

Namespaces:
  Included:  keycloak
  Excluded:  <none>

Resources:
  Included:        *
  Excluded:        <none>
  Cluster-scoped:  auto

Label selector:  <none>

Storage Location:  verrazzano-backup-location

Velero-Native Snapshot PVs:  auto

TTL:  720h0m0s

Hooks:
  Resources:
    verrazzano-sql-backup:
      Namespaces:
        Included:  keycloak
        Excluded:  <none>

      Resources:
        Included:  *
        Excluded:  <none>

      Label selector:  app=mysql

      Pre Exec Hook:
        Container:  mysql
        Command:    bash /etc/mysql/conf.d/mysql-hook.sh -o backup -f sunday.sql
        On Error:   Fail
        Timeout:    5m0s

Backup Format Version:  1.1.0

Started:    2022-07-07 14:56:32 -0700 PDT
Completed:  2022-07-07 14:56:53 -0700 PDT

Expiration:  2022-08-06 14:56:32 -0700 PDT

Total items to be backed up:  91
Items backed up:              91

Velero-Native Snapshots: <none included>

Restic Backups (specify --details for more information):
  Completed:  7
```

</details>

<details>
  <summary>POD Volume backup details</summary></summary>

```shell
 kubectl get podvolumebackups -n velero                  
NAME                      STATUS      CREATED   NAMESPACE   POD                      VOLUME        RESTIC REPO                                                                                                                   STORAGE LOCATION             AGE
mysql-backup-test-b27vj   Completed   3m36s     keycloak    mysql-5df654b5fd-8n4vv   istio-data    s3:https://[objectstoragenamespace].compat.objectstorage.[region].oraclecloud.com/a[backup-name]/[prefix-name]/restic/keycloak   verrazzano-backup-location   3m38s
mysql-backup-test-ldx5t   Completed   3m43s     keycloak    keycloak-0               istio-data    s3:https://[objectstoragenamespace].compat.objectstorage.[region].oraclecloud.com/a[backup-name]/[prefix-name]/restic/keycloak   verrazzano-backup-location   3m45s
mysql-backup-test-m8zxj   Completed   3m45s     keycloak    keycloak-0               istio-envoy   s3:https://[objectstoragenamespace].compat.objectstorage.[region].oraclecloud.com/a[backup-name]/[prefix-name]/restic/keycloak   verrazzano-backup-location   3m45s
mysql-backup-test-nnzgq   Completed   3m35s     keycloak    mysql-5df654b5fd-8n4vv   data          s3:https://[objectstoragenamespace].compat.objectstorage.[region].oraclecloud.com/a[backup-name]/[prefix-name]/restic/keycloak   verrazzano-backup-location   3m38s
mysql-backup-test-qqcj9   Completed   3m40s     keycloak    keycloak-0               cacerts       s3:https://[objectstoragenamespace].compat.objectstorage.[region].oraclecloud.com/a[backup-name]/[prefix-name]/restic/keycloak   verrazzano-backup-location   3m45s
mysql-backup-test-w88q9   Completed   3m38s     keycloak    mysql-5df654b5fd-8n4vv   istio-envoy   s3:https://[objectstoragenamespace].compat.objectstorage.[region].oraclecloud.com/a[backup-name]/[prefix-name]/restic/keycloak   verrazzano-backup-location   3m38s
mysql-backup-test-xg48j   Completed   3m42s     keycloak    keycloak-0               theme         s3:https://[objectstoragenamespace].compat.objectstorage.[region].oraclecloud.com/a[backup-name]/[prefix-name]/restic/keycloak   verrazzano-backup-location   3m45s
```
</details>


#### Opensearch Backup

For `OpenSearch` Verrazzano offers a custom hook that can be used along with `Velero` to perform a backup successfully. 
Due to the nature of transient data handled by Opensearch, the hook invokes `Opensearch` snapshot apis to back up and restore data streams appropriately, 
thereby ensuring there is no loss of data and avoids data corruption as well.

Below example is a sample `Velero` backup [api](https://velero.io/docs/v1.8/api-types/backup/) object that can be invoked to take an Opensearch backup. 

```yaml
apiVersion: velero.io/v1
kind: Backup
metadata:
  name: <backup name>
  namespace: velero
spec:
  includedNamespaces:
    - verrazzano-system
  labelSelector:
    matchLabels:
      verrazzano-component: opensearch
  defaultVolumesToRestic: false
  storageLocation: <backup storage location as referenced in prerequisites>
  hooks:
    resources:
      -
        name: <Opensearch backup resource name>
        includedNamespaces:
          - verrazzano-system
        labelSelector:
          matchLabels:
            statefulset.kubernetes.io/pod-name: vmi-system-es-master-0
        post:                           
          -
            exec:
              container: es-master
              command:
                - /usr/share/opensearch/bin/verrazzano-backup-hook
                - -operation
                - backup
                - -velero-backup-name
                - <backup name used in the yaml>
              onError: Fail
              timeout: 10m
```

In case of Opensearch, we are not backing up the `PersistentVolumes` directly. Instead, we are invoking the Opensearch apis directly to snapshot the data. 

The backup logs are stored in the pod where the hook is executed and can be examined as shown below.

<details>
  <summary>Opensearch backup logs</summary></summary>

```shell
kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/verrazzano-backup-hook-1681009483.log
{"level":"INFO","@timestamp":"2022-07-07T22:17:46.093Z","caller":"verrazzano-backup-hook/main.go:73","message":"Verrazzano backup and restore helper invoked."}
{"level":"INFO","@timestamp":"2022-07-07T22:17:46.093Z","caller":"opensearch/opensearch.go:123","message":"Checking if cluster is healthy"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:46.094Z","caller":"opensearch/opensearch.go:80","message":"Checking if cluster is reachable"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:46.095Z","caller":"opensearch/opensearch.go:116","message":"Cluster 'system' is reachable"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:46.097Z","caller":"opensearch/opensearch.go:161","message":"Cluster health endpoint is reachable now"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:46.098Z","caller":"opensearch/opensearch.go:201","message":"Cluster is reachable and healthy with status as 'green'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:47.650Z","caller":"verrazzano-backup-hook/main.go:130","message":"kubecontext retrieval successful"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:47.650Z","caller":"k8s/k8sHelper.go:32","message":"Populating connection data from backup 'opensearch-backup-test' in namespace 'velero'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:47.650Z","caller":"k8s/k8sHelper.go:129","message":"Fetching Velero backup 'opensearch-backup-test' in namespace 'velero'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:47.801Z","caller":"k8s/k8sHelper.go:44","message":"Detected Velero backup storage location 'verrazzano-backup-location' in namespace 'velero' used by backup 'opensearch-backup-test'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:47.801Z","caller":"k8s/k8sHelper.go:99","message":"Fetching Velero backup storage location 'verrazzano-backup-location' in namespace 'velero'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:48.097Z","caller":"k8s/k8sHelper.go:409","message":"Updating keystore in pod 'vmi-system-es-master-0'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:50.577Z","caller":"k8s/k8sHelper.go:409","message":"Updating keystore in pod 'vmi-system-es-master-1'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:52.760Z","caller":"k8s/k8sHelper.go:409","message":"Updating keystore in pod 'vmi-system-es-master-2'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:55.043Z","caller":"k8s/k8sHelper.go:430","message":"Updating keystore in pod 'vmi-system-es-data-0-6697998869-96cqt'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:57.361Z","caller":"k8s/k8sHelper.go:430","message":"Updating keystore in pod 'vmi-system-es-data-1-794b447c5f-q9ffp'"}
{"level":"INFO","@timestamp":"2022-07-07T22:17:59.758Z","caller":"k8s/k8sHelper.go:430","message":"Updating keystore in pod 'vmi-system-es-data-2-58df5c489-qktfb'"}
{"level":"INFO","@timestamp":"2022-07-07T22:18:01.940Z","caller":"opensearch/opensearch.go:223","message":"Secure settings reloaded sucessfully across all '7' nodes of the cluster"}
{"level":"INFO","@timestamp":"2022-07-07T22:18:01.940Z","caller":"verrazzano-backup-hook/main.go:163","message":"Commencing opensearch backup .."}
{"level":"INFO","@timestamp":"2022-07-07T22:18:01.940Z","caller":"opensearch/opensearch.go:438","message":"Start backup steps ...."}
{"level":"INFO","@timestamp":"2022-07-07T22:18:01.940Z","caller":"opensearch/opensearch.go:231","message":"Registering s3 backend repository 'verrazzano-backup'"}
{"level":"INFO","@timestamp":"2022-07-07T22:18:03.100Z","caller":"opensearch/opensearch.go:254","message":"Snapshot registered successfully !"}
{"level":"INFO","@timestamp":"2022-07-07T22:18:03.100Z","caller":"opensearch/opensearch.go:262","message":"Triggering snapshot with name 'opensearch-backup-test'"}
{"level":"INFO","@timestamp":"2022-07-07T22:18:03.153Z","caller":"opensearch/opensearch.go:274","message":"Snapshot triggered successfully !"}
{"level":"INFO","@timestamp":"2022-07-07T22:18:03.153Z","caller":"opensearch/opensearch.go:280","message":"Checking snapshot progress with name 'opensearch-backup-test'"}
{"level":"INFO","@timestamp":"2022-07-07T22:18:03.168Z","caller":"utilities/basicUtils.go:51","message":"Snapshot 'opensearch-backup-test' is in progress . Wait for '11' seconds ..."}
{"level":"INFO","@timestamp":"2022-07-07T22:18:14.191Z","caller":"opensearch/opensearch.go:316","message":"Snapshot 'opensearch-backup-test' complete"}
{"level":"INFO","@timestamp":"2022-07-07T22:18:14.191Z","caller":"opensearch/opensearch.go:323","message":"Backup in progress. total shards = 11, successfull shards backed up = 11, indices = [.ds-verrazzano-system-000001 .kibana_1 .ds-verrazzano-application-velero-000001], data streams = [verrazzano-application-velero verrazzano-system], "}
{"level":"INFO","@timestamp":"2022-07-07T22:18:14.191Z","caller":"verrazzano-backup-hook/main.go:169","message":"OPENSEARCH backup was successfull"}
```
</details>


They are also available as part of the Velero backup logs.  

### Scheduled Backups 

Velero also supports scheduled backups is used as a repeatable request for the Velero server to perform a backup for a given cron notation. 
Once created, the Velero Server will start the backup process. 
It will then wait for the next valid point of the given cron expression and execute the backup process on a repeating basis.

Schedule API is documented [here](https://velero.io/docs/v1.8/api-types/schedule/).  






