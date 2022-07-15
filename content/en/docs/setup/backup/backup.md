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

Before proceeding the following information about Object Store should be provided as an input: 

- Create an Oracle Cloud Object Storage bucket in any compartment of your Oracle Cloud tenancy. Make a note of the bucket name and tenancy name for reference.  
  Refer to this [page](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm#usingconsole) for more information about creating a bucket with Object Storage. 
- Object store prefix name. This will be a child folder under the bucket automatically created by the backup component.
- Object store region information.  
- Verrazzano backup component requires object store to be Amazon S3 compatible. As a result you need to generate the signing key required to authenticate with Amazon S3.
  Follow these steps to create a [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#To4). 

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
kubectl create secret generic -n verrazzano-backup verrazzano-backup-creds --from-file=cloud=backup-secret.txt
```

**_NOTE:_** Ensure the `backup-secret.txt` file is cleaned up after the kubernetes secret is created to avoid misuse of sensitive data.  

- Create a `BackupStorageLocation` which the backup component will reference for subsequent backups. Below is an example of the `BackupStorageLocation`. 
  Refer this [page](https://velero.io/docs/v1.8/api-types/backupstoragelocation/) for more information.

```yaml
apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: verrazzano-backup-location
  namespace: verrazzano-backup
spec:
  provider: aws
  objectStorage:
    bucket: example-verrazzano
    prefix: backup-demo
  credential:
    name: verrazzano-backup-creds
    key: cloud
  config:
    region: us-phoenix-1
    s3ForcePathStyle: "true"
    s3Url: https://mytenancy.compat.objectstorage.us-phoenix-1.oraclecloud.com
```


### Taking a Backup 

At this point you are ready to back up a namespace or a component with Velero. 

For certain components Verrazzano offers specialized `hooks` to ensure backup which can be used in conjunction with Velero as outline [here](https://velero.io/docs/v1.8/backup-hooks/).   

Currently, the following components can be backed up with hooks:
- MySQL
- OpenSearch 

We will now take a look on how to take a component specific backup. 

#### MySQL Backup 

For `MySQL` Verrazzano offers a custom hook that can be used along with `Velero` to perform a backup successfully. 

Below example is a sample `Velero` backup [api](https://velero.io/docs/v1.8/api-types/backup/) object that can be invoked to take a MySQL backup. 

```yaml
apiVersion: velero.io/v1
kind: Backup
metadata:
  name: verrazzano-mysql-backup-example
  namespace: verrazzano-backup
spec:
  includedNamespaces:
  - keycloak
  defaultVolumesToRestic: true
  storageLocation: verrazzano-backup-location
  hooks:
    resources:
      - name: mysql-backup
        includedNamespaces:
          - keycloak       
        labelSelector:
          matchLabels:
            app: mysql
        pre:
          - exec:
              container: mysql
              command:
                - bash
                - /etc/mysql/conf.d/mysql-hook.sh
                - -o backup
                - -f mysql-backup-test.sql
              onError: Fail
              timeout: 5m
```

We can monitor the Velero backup object to understand the progress of our backup. 

<details>
  <summary>MySQL Backup Progress</summary>

```shell
velero backup get verrazzano-mysql-backup-example -n verrazzano-backup                                                                   
NAME                              STATUS       ERRORS   WARNINGS   CREATED                         EXPIRES   STORAGE LOCATION             SELECTOR
verrazzano-mysql-backup-example   InProgress   0        0          2022-07-07 14:56:32 -0700 PDT   29d       verrazzano-backup-location   <none>
```
</details>

<details>
  <summary>MySQL Backup Object details</summary>

```shell
# The backup object details and progress can be viewed by executing the following command

velero backup describe verrazzano-mysql-backup-example -n verrazzano-backup

# Sample output 

Name:         verrazzano-mysql-backup-example
Namespace:    verrazzano-backup
Labels:       velero.io/storage-location=verrazzano-backup-location
Annotations:  kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"velero.io/v1","kind":"Backup","metadata":{"annotations":{},"name":"verrazzano-mysql-backup-example","namespace":"verrazzano-backup"},"spec":{"defaultVolumesToRestic":true,"hooks":{"resources":[{"includedNamespaces":["keycloak"],"labelSelector":{"matchLabels":{"app":"mysql"}},"name":"verrazzano-sql-backup","pre":[{"exec":{"command":["bash","/etc/MySQL/conf.d/MySQL-hook.sh","-o backup","-f sunday.sql"],"container":"mysql","onError":"Fail","timeout":"5m"}}]}]},"includedNamespaces":["keycloak"],"storageLocation":"verrazzano-backup-location"}}

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
    mysql-backup:
      Namespaces:
        Included:  keycloak
        Excluded:  <none>

      Resources:
        Included:  *
        Excluded:  <none>

      Label selector:  app=MySQL

      Pre Exec Hook:
        Container:  MySQL
        Command:    bash /etc/mysql/conf.d/mysql-hook.sh -o backup -f mysql-backup-test.sql
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
  <summary>POD Volume backup details</summary>

```shell
# The following command lists all the pod volume backups taken by velero. 
kubectl get podvolumebackups -n verrazzano-backup 
```
</details>


#### OpenSearch Backup

For `OpenSearch` Verrazzano provides a custom hook that can be used along with `Velero` to perform a backup successfully. 
Due to the nature of transient data handled by OpenSearch, the hook invokes `OpenSearch` snapshot apis to back up and restore data streams appropriately, 
thereby ensuring there is no loss of data and avoids data corruption as well.

Below example is a sample `Velero` backup [api](https://velero.io/docs/v1.8/api-types/backup/) object that can be invoked to take an OpenSearch backup. 

```yaml
apiVersion: velero.io/v1
kind: Backup
metadata:
  name: verrazzano-opensearch-backup
  namespace: verrazzano-backup
spec:
  includedNamespaces:
    - verrazzano-system
  labelSelector:
    matchLabels:
      verrazzano-component: opensearch
  defaultVolumesToRestic: false
  storageLocation:  verrazzano-backup-location
  hooks:
    resources:
      - name: opensearch-backup-test
        includedNamespaces:
          - verrazzano-system
        labelSelector:
          matchLabels:
            statefulset.kubernetes.io/pod-name: vmi-system-es-master-0
        post:                           
          - exec:
              container: es-master
              command:
                - /usr/share/opensearch/bin/verrazzano-backup-hook
                - -operation
                - backup
                - -velero-backup-name
                - verrazzano-opensearch-backup
              onError: Fail
              timeout: 10m
```

In case of OpenSearch, we are not backing up the `PersistentVolumes` directly. Instead, we are invoking the OpenSearch apis directly to snapshot the data. 

Once the backup is executed, the hook logs can be seen in the `velero backup logs` command. Additionally, the hook logs are also stored under `/tmp` folder in the pod itself.

<details>
  <summary>OpenSearch backup logs</summary></summary>

```shell
# To display the logs from the backup execute the following command
velero backup logs verrazzano-opensearch-backup -n verrazzano-backup

# To examine the hook logs exec into the pod as shown below
kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/verrazzano-backup-hook-1681009483.log
```
</details>

### Scheduled Backups 

Velero also supports scheduled backups is used as a repeatable request for the Velero server to perform a backup for a given cron notation. 
Once created, the Velero Server will start the backup process. 
It will then wait for the next valid point of the given cron expression and execute the backup process on a repeating basis.

Schedule API is documented [here](https://velero.io/docs/v1.8/api-types/schedule/).  






