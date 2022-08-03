---
title: "Backup"
description: "Backup component specific persistent data and configurations"
linkTitle: Backup
weight: 2
draft: false
---

Before proceeding ensure the backup operator(s) is installed and configured properly as indicated  [here](/docs/setup/backup/prerequisites/#rancher-backup-operator-prerequisite).

As stated earlier Verrazzano offers [velero](https://velero.io/docs/v1.8/) and [rancher-backup](https://rancher.com/docs/rancher/v2.5/en/backups/) to perform backup and recovery at a component level or as a platform as a whole.

In the following section we will be going over the following configurations:

- [RancherBackup](https://rancher.com/docs/rancher/v2.5/en/backups/) operator to back up persistent data and configuration related to Rancher.

- Velero [hooks](https://velero.io/docs/v1.8/backup-hooks/), that have been implemented to ensure a consistent backup experience for the components: 
  - MySQL
  - OpenSearch
  

For all other components refer to Velero documentation for taking [backups](https://velero.io/docs/v1.8/backup-reference/).


{{< tabs tabTotal="3" >}}
{{< tab tabName="RancherBackup" >}}
<br>

## Rancher Backup

To initiate a Rancher backup create the following example custom resource YAML that will use S3 compatible object store as a backend.

The app uses the `credentialSecretNamespace` value to determine where to look for the S3 backup secret.

In the [prerequisites](/docs/setup/backup/prerequisites/#rancher-backup-operator-prerequisite) section, we had created the secret in `verrazzano-backup` namespace.

```yaml
apiVersion: resources.cattle.io/v1
kind: Backup
metadata:
  name: rancher-backup-test
spec:
  storageLocation:
    s3:
      credentialSecretName: rancher-backup-creds
      credentialSecretNamespace: verrazzano-backup
      bucketName: myvz-bucket
      folder: rancher-backup
      region: us-phoenix-1
      endpoint: mytenancy.compat.objectstorage.us-phoenix-1.oraclecloud.com
  resourceSetName: rancher-resource-set
```

Once a Backup custom resource is created, the `rancher-backup` operator calls the kube-apiserver to get the resources predefined with `rancher-backup` CRDs.

The operator then creates the backup file in the .tar.gz format and stores it in the location configured in the Backup resource in storageLocation field.

### Scheduled Backups

Similar to Velero, rancher-backup also allows [scheduled backups](https://rancher.com/docs/rancher/v2.5/en/backups/configuration/backup-config/).  

<br/>

{{< /tab >}}
{{< tab tabName="Velero MySQL Backup" >}}
<br>

### Velero MySQL Backup

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

The above example will take a backup of the keycloak namespace and mysql data
- `defaultVolumesToRestic` needs to be `true` so that Velero can back up the mysql PVC. 
- The hook needs to be `pre` as this wil ensure the operation is performed before the PVC backup is taken .
- The command used as part of the hook is a shell script which accepts an argument to denote operation and a filename.
- The container on which the hook needs to be executed is identified by the pod label selectors, followed by the container name.

We can monitor the Velero backup object to understand the progress of our backup.  

<details>
  <summary>MySQL Backup Progress</summary>

```shell
# The status in the below putput indicates the backup progress.

velero backup get verrazzano-mysql-backup-example -n verrazzano-backup                                                                   
NAME                              STATUS       ERRORS   WARNINGS   CREATED                         EXPIRES   STORAGE LOCATION             SELECTOR
verrazzano-mysql-backup-example   InProgress   0        0          2022-07-07 14:56:32 -0700 PDT   29d       verrazzano-backup-location   <none>
```
</details>

<details>
  <summary>MySQL Backup Object details</summary>

```shell
# The backup object details and progress can be viewed by executing the following command.

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
  <summary>Pod Volume backup details</summary>

```shell
# The following command lists all the pod volume backups taken by Velero.
 
kubectl get podvolumebackups -n verrazzano-backup 
```
</details>


### Scheduled Backups

Velero also supports a schedule [API](https://velero.io/docs/v1.8/api-types/schedule/).
It is a repeatable request that is sent to the Velero server to perform a backup for a given cron notation.
Once the `schedule` object is created, the Velero Server will start the backup process.
It will then wait for the next valid point of the given cron expression and execute the backup process on a repeating basis.

<br/>


{{< /tab >}}
{{< tab tabName="Velero OpenSearch Backup" >}}
<br>

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

The above example will take a backup of the opensearch components
- In this case we are not backing up the `PersistentVolumes` directly, rather executing a hook that invokes the OpenSearch APIs directly to snapshot the data.
- `defaultVolumesToRestic` needs to be `false` so that Velero ignores the associated PVC's.
- The hook can be `pre` or `post` in this case.
- The command used as part of the hook requires an operation flag and the velero backup name as an input. 
- The container on which the hook needs to be executed is identified by the pod label selectors, followed by the container name. 
  In this case its `statefulset.kubernetes.io/pod-name: vmi-system-es-master-0`

Once the backup is executed, the hook logs can be seen in the `velero backup logs` command. Additionally, the hook logs are also stored under the `/tmp` folder in the pod itself.

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

Velero also supports a `Schedule` [API](https://velero.io/docs/v1.8/api-types/schedule/).
That is a repeatable request is sent to the Velero server to perform a backup for a given cron notation.
Once the `Schedule` object is created, the Velero server will start the backup process.
It will then wait for the next valid point of the given cron expression and execute the backup process on a repeating basis.

<br/>