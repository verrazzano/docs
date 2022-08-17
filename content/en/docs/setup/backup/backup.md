---
title: "Backup"
description: "Back up component-specific persistent data and configurations"
linkTitle: Backup
weight: 2
draft: false
---

Verrazzano provides [Velero](https://velero.io/docs/v1.8/) and [rancher-backup](https://rancher.com/docs/rancher/v2.5/en/backups/) for backup and recovery at the component and platform level.
First, ensure that the backup component prerequisites are met, as indicated [here]({{< relref "docs/setup/backup/prerequisites.md" >}}).

The following sections provide detailed configuration information for:

- The [rancher-backup](https://rancher.com/docs/rancher/v2.5/en/backups/) operator, to back up persistent data and Rancher-related configuration.

- Velero [hooks](https://velero.io/docs/v1.8/backup-hooks/), to ensure a consistent backup experience for these components:
  - MySQL
  - OpenSearch
  - For all other components, refer to the Velero [Backup Reference](https://velero.io/docs/v1.8/backup-reference/).


{{< tabs tabTotal="3" >}}
{{< tab tabName="Rancher Backup" >}}
<br>

## Rancher Backup

To initiate a Rancher backup, create the following example custom resource YAML file that uses an Amazon S3 compatible object store as a backend.
The operator uses the `credentialSecretNamespace` value to determine where to look for the Amazon S3 backup secret.
Note that in the [prerequisites]({{< relref "docs/setup/backup/prerequisites#component-specific-prerequisites" >}}) example, you previously created the secret in the `verrazzano-backup` namespace.

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

The operator creates the backup file, in the `*.tar.gz` format, and stores it in the location configured in the `storageLocation` field.

### Scheduled backups

Similar to Velero, rancher-backup allows [scheduled backups](https://rancher.com/docs/rancher/v2.5/en/backups/configuration/backup-config/).  

<br/>

{{< /tab >}}
{{< tab tabName="MySQL Backup" >}}
<br>

### MySQL Backup

For MySQL, Verrazzano provides a custom hook that you can use along with Velero, to perform a backup.
The following example shows a sample Velero `Backup` [API](https://velero.io/docs/v1.8/api-types/backup/) object that you can invoke to make a MySQL backup.

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

The preceding example backs up the `keycloak` namespace and `mysql` data.
- So that Velero can back up the MySQL Persistent Volume Claim (PVC), `defaultVolumesToRestic` must be `true`.
- The hook needs to be `pre` as this will ensure that the operation is performed before the PVC backup is taken.
- The command used in the hook is a shell script, which accepts an argument to denote the operation and a file name.
- The container on which the hook must be executed is identified by the pod label selectors, followed by the container name.

To understand the progress of the backup, you can monitor the Velero `Backup` object.

<details>
  <summary>MySQL backup progress</summary>

```shell
# The status in the following output indicates the backup progress

$ velero backup get verrazzano-mysql-backup-example -n verrazzano-backup                                                                   
NAME                              STATUS       ERRORS   WARNINGS   CREATED                         EXPIRES   STORAGE LOCATION             SELECTOR
verrazzano-mysql-backup-example   InProgress   0        0          2022-07-07 14:56:32 -0700 PDT   29d       verrazzano-backup-location   <none>
```
</details>

<details>
  <summary>MySQL Backup object details</summary>

```shell
# The backup object details and progress can be viewed by executing the following command

$ velero backup describe verrazzano-mysql-backup-example -n verrazzano-backup

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
  <summary>Pod volume backup details</summary>

```shell
# The following command lists all the pod volume backups taken by Velero

$ kubectl get podvolumebackups -n verrazzano-backup
```
</details>

<br>

### Scheduled backups

Velero supports a `Schedule` [API](https://velero.io/docs/v1.8/api-types/schedule/) that
is a repeatable request that is sent to the Velero server to perform a backup for a given cron notation.
After the `Schedule` object is created, the Velero server will start the backup process.
Then, it will wait for the next valid point in the given cron expression and execute the backup process on a repeating basis.

<br/>


{{< /tab >}}
{{< tab tabName="OpenSearch Backup" >}}
<br>

### OpenSearch Backup

For OpenSearch, Verrazzano provides a custom hook that you can use along with Velero while invoking a backup.
Due to the nature of transient data handled by OpenSearch, the hook invokes OpenSearch snapshot APIs to back up and restore data streams appropriately,
thereby ensuring that there is no loss of data and avoids data corruption as well.

The following example shows a sample Velero `Backup` [API](https://velero.io/docs/v1.8/api-types/backup/) object that you can invoke to make an OpenSearch backup.

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

The preceding example backs up the OpenSearch components:
- In this case, you are not backing up the `PersistentVolumes` directly, rather executing a hook that invokes the OpenSearch APIs to take a snapshot of the data.
- So that Velero ignores the associated PVC's, `defaultVolumesToRestic` needs to be `false`.
- In this case, the hook can be `pre` or `post`.
- The command used in the hook requires an `operation` flag and the Velero backup name as an input.
- The container on which the hook needs to be executed is identified by the pod label selectors, followed by the container name.
  In this case, it's `statefulset.kubernetes.io/pod-name: vmi-system-es-master-0`.

After the backup is executed, you can see the hook logs using the `velero backup logs` command. Additionally, the hook logs are stored under the `/tmp` folder in the pod.

<details>
  <summary>OpenSearch backup logs</summary></summary>

```shell
# To display the logs from the backup, execute the following command
$ velero backup logs verrazzano-opensearch-backup -n verrazzano-backup

# To examine the hook logs, exec into the pod as shown
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/verrazzano-backup-hook-1681009483.log
```
</details>

<br>

### Scheduled backups

Velero supports a `Schedule` [API](https://velero.io/docs/v1.8/api-types/schedule/)
that is a repeatable request that is sent to the Velero server to perform a backup for a given cron notation.
After the `Schedule` object is created, the Velero server will start the backup process.
Then, it will then wait for the next valid point in the given cron expression and execute the backup process on a repeating basis.

<br/>
