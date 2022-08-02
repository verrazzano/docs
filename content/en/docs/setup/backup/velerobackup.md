---
title: "Velero Backup"
description: "Backup persistent data using the Velero operator"
linkTitle: Velero Backup
weight: 1
draft: false
---

Verrazzano offers specialized `hooks` to ensure a consistent backup experience with Velero.  More context on hooks can be found [here](https://velero.io/docs/v1.8/backup-hooks/).

Currently, the following components have in built hooks:
- MySQL
- OpenSearch

For all other components refer to Velero documentation for taking [backups](https://velero.io/docs/v1.8/backup-reference/).

### MySQL Backup 

For `MySQL` Verrazzano offers a custom hook that can be used along with Velero to perform a backup. 

Below example is a sample Velero `Backup` [api](https://velero.io/docs/v1.8/api-types/backup/) object that can be invoked to take a MySQL backup. 

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


### OpenSearch Backup

For OpenSearch Verrazzano provides a custom hook that can be used along with Velero while invoking a backup. 
Due to the nature of transient data handled by OpenSearch, the hook invokes OpenSearch snapshot apis to back up and restore data streams appropriately, 
thereby ensuring there is no loss of data and avoids data corruption as well.

Below example is a sample Velero backup [api](https://velero.io/docs/v1.8/api-types/backup/) object that can be invoked to take an OpenSearch backup. 

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

Velero also supports a schedule [API](https://velero.io/docs/v1.8/api-types/schedule/). 
It is a repeatable request is sent to the Velero server to perform a backup for a given cron notation. 
Once the `schedule` object is created, the Velero Server will start the backup process. 
It will then wait for the next valid point of the given cron expression and execute the backup process on a repeating basis.



