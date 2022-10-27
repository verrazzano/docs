---
title: "Backup"
description: "Back up component-specific persistent data and configurations"
linkTitle: Backup
weight: 2
draft: false
---

Verrazzano provides [Velero](https://velero.io/docs/v1.8/), [rancher-backup](https://rancher.com/docs/rancher/v2.5/en/backups/), and  [MySQL Operator](https://dev.mysql.com/doc/mysql-operator/en/mysql-operator-backups.html) for backup and recovery at the component and platform level.
First, ensure that the backup component prerequisites are met, as indicated [here]({{< relref "/docs/uninstall/backup/prerequisites.md" >}}).

The following sections provide detailed configuration information for:

- The [MySQL Operator](https://dev.mysql.com/doc/mysql-operator/en/) to back up persistent data stored in the MySQL database.
- The [rancher-backup](https://rancher.com/docs/rancher/v2.5/en/backups/) operator, to back up persistent data and Rancher-related configuration. See [Rancher backup](#rancher-backup).

- Velero [hooks](https://velero.io/docs/v1.8/backup-hooks/), to ensure a consistent backup experience for these components:
  - OpenSearch. See [OpenSearch backup](#opensearch-backup).
  - For all other components, beside `Rancher` and `MySQL`, refer to the Velero [Backup Reference](https://velero.io/docs/v1.8/backup-reference/).

## MySQL backup

To initiate a MySQL backup, create the following example custom resource YAML file that uses the OCI object store as a backend.
The operator uses the `credentials` to authenticate with the OCI object store.

```yaml
$ kubectl apply -f - <<EOF
  apiVersion: mysql.oracle.com/v2
  kind: MySQLBackup
  metadata:
      name: <backup name>
      namespace: keycloak
  spec:
    clusterName: mysql
    backupProfile:       
      name: <backupProfileName>
      dumpInstance:              
        storage:
          ociObjectStorage:
            prefix: <prefix name. This folder will be auto created>
            bucketName: <object store bucket. This must be exist as noted in pre-requisites section>
            credentials: mysql-backup-secret
EOF
```

**NOTE:**
- In the [prerequisites]({{< relref "/docs/uninstall/backup/prerequisites#component-specific-prerequisites" >}}) example, you created the secret `mysql-backup-secret` in the `keycloak` namespace.
- The `clustername` has to be `mysql`.
- The `namespace` has to be `keycloak`.

The following is an example:

```yaml
$ kubectl apply -f - <<EOF
  apiVersion: mysql.oracle.com/v2
  kind: MySQLBackup
  metadata:
      name: mysql-backup
      namespace: keycloak
  spec:
    clusterName: mysql
    backupProfile:       
      name: mysqlOneTime  
      dumpInstance:              
        storage:
          ociObjectStorage:
            prefix: mysql-test
            bucketName: mysql-bucket
            credentials: mysql-backup-secret
EOF
```
### Scheduled backups

MySQL allows scheduled backups by implementing a cron job on [MySQL Operator](https://dev.mysql.com/doc/mysql-operator/en/mysql-operator-backups.html) for Kubernetes.


## Rancher backup

To initiate a Rancher backup, create the following example custom resource YAML file that uses an Amazon S3 compatible object store as a backend.
The operator uses the `credentialSecretNamespace` value to determine where to look for the Amazon S3 backup secret.
Note that in the [prerequisites]({{< relref "/docs/uninstall/backup/prerequisites#component-specific-prerequisites" >}}) example, you previously created the secret in the `verrazzano-backup` namespace.

```yaml
$ kubectl apply -f - <<EOF
  apiVersion: resources.cattle.io/v1
  kind: Backup
  metadata:
    name: <rancher-backup-name>
  spec:
    storageLocation:
      s3:
        credentialSecretName: <rancher-backup-creds-name>
        credentialSecretNamespace: <namespace where credential object was created>
        bucketName: <object store bucket. This must be exist as noted in pre-requisites section>
        folder: <folder name. This folder will be auto created>
        region: <region name where bucket exists>
        endpoint: <object store endpoint configuration>
    resourceSetName: rancher-resource-set
EOF
```

**NOTE:** In the [prerequisites]({{< relref "/docs/uninstall/backup/prerequisites#component-specific-prerequisites" >}}) example, you previously created the secret in the `verrazzano-backup` namespace.

The following is an example:

```yaml
$ kubectl apply -f - <<EOF
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
EOF
```


The operator creates the backup file, in the `*.tar.gz` format, and stores it in the location configured in the `storageLocation` field.

### Scheduled backups

rancher-backup implements scheduled backups as indicated here, [scheduled backups](https://rancher.com/docs/rancher/v2.5/en/backups/configuration/backup-config/).  


## OpenSearch backup

For OpenSearch, Verrazzano provides a custom hook that you can use along with Velero while invoking a backup.
Due to the nature of transient data handled by OpenSearch, the hook invokes OpenSearch snapshot APIs to back up and restore data streams appropriately,
thereby ensuring that there is no loss of data and avoids data corruption as well.

The following example shows a sample Velero `Backup` [API](https://velero.io/docs/v1.8/api-types/backup/) object that you can invoke to make an OpenSearch backup.

```yaml
$ kubectl apply -f - <<EOF
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
EOF
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
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero

# Fetch the log file name as shown
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- ls -al /tmp | grep verrazzano-backup-hook | tail -n 1 | awk '{print $NF}'

# To examine the hook logs, exec into the pod as shown, and use the file name retrieved previously
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/<log-file-name>
```
</details>

<br>

### Scheduled backups

Velero supports a `Schedule` [API](https://velero.io/docs/v1.8/api-types/schedule/)
that is a repeatable request that is sent to the Velero server to perform a backup for a given cron notation.
After the `Schedule` object is created, the Velero server will start the backup process.
Then, it will then wait for the next valid point in the given cron expression and execute the backup process on a repeating basis.

<br/>
