---
title: "OpenSearch"
description: "Back up and restore OpenSearch"
linkTitle: OpenSearch
weight: 2
draft: false
---

Verrazzano provides a ready-to-use, OpenSearch deployment that gives you access to all the log messages from various microservices running on the platform.
There are scenarios where you may want to back up your OpenSearch data and restore it.

Verrazzano uses Velero to facilitate backing up and restoring OpenSearch data.

- [Velero operator prerequisites](#velero-operator-prerequisites)
- [OpenSearch backup using Velero](#opensearch-backup-using-velero)
- [OpenSearch restore using Velero](#opensearch-restore-using-velero)
- [OpenSearch restore in an existing cluster using OpenSearch API](#opensearch-restore-in-an-existing-cluster-using-opensearch-api)

**NOTE**: When upgrading, follow the backup documentation for your existing Verrazzano version, not the version to which you are upgrading. 

## Velero operator prerequisites

Before proceeding with an OpenSearch backup or restore operation, the following details should be kept handy:

- Object store bucket name.
    - An Amazon S3 compatible object storage bucket. This can be an Oracle Cloud Object Storage bucket in any compartment of your Oracle Cloud tenancy.
        - For reference, make a note of the bucket name and tenancy name.
        - For more information about creating a bucket with Object Storage, see [Managing Buckets](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm).
    - For private clouds, enterprise networks, or air-gapped environments, this could be MinIO or an equivalent object store solution.
- Object store prefix name. This will be a child folder under the bucket, which the backup component creates.
- Object store region name.
- Object store signing key.
   - A signing key, which is required to authenticate with the Amazon S3 compatible object store; this is an Access Key/Secret Key pair.
   - In Oracle Cloud Infrastructure, you or your administrator creates the Customer Secret Key.
      - An associated Access Key will be generated for the secret key.
      - To create a Customer Secret Key, see [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#create-secret-key).



To back up or restore OpenSearch, you must first enable Velero.

1. The following configuration shows you how to enable `velero` with a `prod` installation profile.
{{< clipboard >}}

  ```yaml
    $ kubectl apply -f -<<EOF
      apiVersion: install.verrazzano.io/v1beta1
      kind: Verrazzano
      metadata:
        name: example-verrazzano
      spec:
        profile: prod
        components:    
          velero:
            enabled: true
EOF
  ```
{{< /clipboard >}}

  **NOTE**: The OpenSearch back up and restore operation is supported _only_ on `prod` installation profiles with a multinode OpenSearch configuration.

2. After Velero is enabled, verify that the Velero pods are running in the `verrazzano-backup` namespace.
{{< clipboard >}}

```shell
# Sample of pods running after enabling the velero component
$ kubectl get pod -n verrazzano-backup
NAME                      READY   STATUS    RESTARTS   AGE
restic-ndxfk              1/1     Running   0          21h
velero-5ff8766fd4-xbn4z   1/1     Running   0          21h
  ```
{{< /clipboard >}}

3. Velero requires a secret to communicate with the S3 compatible object store, so we create a `backup-secret.txt` file, which has the object store credentials.
{{< clipboard >}}

   ```backup-secret.txt
   [default]
   aws_access_key_id=<object store access key>
   aws_secret_access_key=<object store secret key>
   ```
{{< /clipboard >}}
4. In the namespace `verrazzano-backup`, create a Kubernetes secret, for example `verrazzano-backup-creds`.
{{< clipboard >}}

   ```shell
   $ kubectl create secret generic -n <backup-namespace> <secret-name> --from-file=<key>=<full_path_to_creds_file>
   ```

   The following is an example:
   ```shell
   $ kubectl create secret generic -n verrazzano-backup verrazzano-backup-creds --from-file=cloud=backup-secret.txt
   ```

   **NOTE**: To avoid misuse of sensitive data, ensure that the `backup-secret.txt` file is deleted after the Kubernetes secret is created.
{{< /clipboard >}}

5. Create a `BackupStorageLocation` resource, which the backup component will reference for subsequent backups. See the following `BackupStorageLocation` example.
   For more information, see [Backup Storage Location](https://velero.io/docs/v1.9/api-types/backupstoragelocation/) in the Velero documentation.
{{< clipboard >}}

  ```yaml
   $ kubectl apply -f -<<EOF
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
EOF
  ```
{{< /clipboard >}}
## OpenSearch backup Using Velero

For OpenSearch, Verrazzano provides a custom hook that you can use along with Velero while invoking a backup.
Due to the nature of transient data handled by OpenSearch, the hook invokes the OpenSearch snapshot APIs to back up data streams appropriately,
thereby ensuring that there is no loss of data and avoids data corruption as well.

The following example shows a sample Velero `Backup` [API](https://velero.io/docs/v1.9/api-types/backup/) resource that you can create to initiate an OpenSearch backup.
{{< clipboard >}}

```yaml
  $ kubectl apply -f - <<EOF
  apiVersion: velero.io/v1
  kind: Backup
  metadata:
    name: verrazzano-opensearch-backup
    namespace: verrazzano-backup
  spec:
    includedNamespaces:
      - verrazzano-logging
    labelSelector:
      matchLabels:
        opster.io/opensearch-cluster: opensearch
    defaultVolumesToRestic: false
    storageLocation:  verrazzano-backup-location
    hooks:
      resources:
        - name: opensearch-backup-test
          includedNamespaces:
            - verrazzano-logging
          labelSelector:
            matchLabels:
              statefulset.kubernetes.io/pod-name: opensearch-es-master-0
          post:                           
            - exec:
                container: opensearch
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
{{< /clipboard >}}

The preceding example backs up the OpenSearch components:
- In this case, you are not backing up the `PersistentVolumes` directly, rather running a hook that invokes the OpenSearch APIs to take a snapshot of the data.
- The `defaultVolumesToRestic` is set to `false` so that Velero ignores the associated PVCs.
- In this case, the hook can be `pre` or `post`.
- The command used in the hook requires an `operation` flag and the Velero backup name as an input.
- The container on which the hook needs to be run defaults to the first container in the pod.
  In this case, it's `statefulset.kubernetes.io/pod-name: opensearch-es-master-0`.

After the backup is processed, you can see the hook logs using the `velero backup logs` command. Additionally, the hook logs are stored under the `/tmp` folder in the pod.

<details>
  <summary>OpenSearch backup logs</summary></summary>
{{< clipboard >}}

```shell
# To display the logs from the backup, run the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero

# Fetch the log file name as shown
$ kubectl exec -it opensearch-es-master-0 -n verrazzano-logging -- ls -al /tmp | grep verrazzano-backup-hook | tail -n 1 | awk '{print $NF}'

# To examine the hook logs, exec into the pod as shown, and use the file name retrieved previously
$ kubectl exec -it opensearch-es-master-0 -n verrazzano-logging -- cat /tmp/<log-file-name>
```
{{< /clipboard >}}
</details>

<br>

### OpenSearch scheduled backups

Velero supports a `Schedule` [API](https://velero.io/docs/v1.9/api-types/schedule/)
that is a repeatable request that is sent to the Velero server to perform a backup for a given cron notation.
After the `Schedule` object is created, the Velero server will start the backup process.
Then, it will wait for the next valid point in the given cron expression and run the backup process on a repeating basis.

<br/>

## OpenSearch restore using Velero

For OpenSearch, Verrazzano provides a custom hook that you can use along with Velero to perform a restore operation.
Due to the nature of transient data handled by OpenSearch, the hook invokes OpenSearch snapshot APIs to restore data streams appropriately,
thereby ensuring there is no loss of data and avoids data corruption as well.

If you restore OpenSearch to a different cluster, create a Velero `BackupStorageLocation` resource in the new cluster
that points to the same backup storage location configured in the original cluster. This ensures that the Velero
resources created by the original cluster’s backup are automatically synced to the new cluster. Once the sync completes,
you will be able to access the backup from the original cluster on the new cluster. It is recommended to configure the
`BackupStorageLocation` on the new cluster as read-only by setting `accessMode` to
`ReadOnly` in the `BackupStorageLocation` spec. This ensures that the backup in the object store  is not modified from
the new cluster. For more information, see
[Backup Storage Location](https://velero.io/docs/v1.9/api-types/backupstoragelocation/#backup-storage-location) in the
Velero documentation.

To initiate an OpenSearch restore operation, first delete the existing OpenSearch cluster running on the system and all related data.

1. Scale down the Verrazzano Monitoring Operator. This is required because the operator manages the life cycle of the OpenSearch cluster, so scaling it down to zero ensures that it does not interfere with the restore operation.
   The restore operation also ensures that this operator is scaled back up to return the system to its previous state.
{{< clipboard >}}
 ```shell
  $ kubectl scale deploy -n verrazzano-logging opensearch-operator-controller-manager --replicas=0
  ```
{{< /clipboard >}}

2. Delete the OpenSearch components.
{{< clipboard >}}
 ```shell
# These are sample commands to demonstrate the OpenSearch restore process
$ kubectl delete sts -n verrazzano-logging -l opster.io/opensearch-cluster=opensearch
$ kubectl delete deploy -n verrazzano-logging -l opster.io/opensearch-cluster=opensearch
$ kubectl delete pvc -n verrazzano-logging -l opster.io/opensearch-cluster=opensearch
 ```
{{< /clipboard >}}

3. To perform an OpenSearch restore operation, you can invoke the following example Velero `Restore` [API](https://velero.io/docs/v1.9/api-types/restore/) object.
{{< clipboard >}}
 ```yaml
   $ kubectl apply -f - <<EOF
   apiVersion: velero.io/v1
   kind: Restore
   metadata:
     name: verrazzano-opensearch-restore
     namespace: verrazzano-backup
   spec:
     backupName: verrazzano-opensearch-backup
     includedNamespaces:
       - verrazzano-logging
     labelSelector:
       matchLabels:
         opster.io/opensearch-cluster: opensearch
     restorePVs: false
     hooks:
       resources:
       - name: opensearch-test
         includedNamespaces:
         - verrazzano-logging
         labelSelector:
           matchLabels:            
             statefulset.kubernetes.io/pod-name: opensearch-es-master-0
         postHooks:
         - init:
           timeout: 30m
           initContainers:
             - args:
                 - /usr/share/opensearch/bin/verrazzano-backup-hook --operation=pre-restore --velero-backup-name=verrazzano-opensearch-backup
               command:
                 - sh
                 - -c
               image: ghcr.io/verrazzano/opensearch:2.3.0-20230928071551-b6247ad8ac8
               imagePullPolicy: Always
               name: pre-hook
         - exec:
             container: opensearch
             command:
             - /usr/share/opensearch/bin/verrazzano-backup-hook
             - -operation
             - restore
             - -velero-backup-name
             - verrazzano-opensearch-backup
             waitTimeout: 30m
             execTimeout: 30m
             onError: Fail
EOF
   ```
{{< /clipboard >}}

   The preceding example will restore an OpenSearch cluster from an existing backup.
   - In this case, you are not restoring `PersistentVolumes` directly, rather running a hook that invokes the OpenSearch APIs to restore them from an existing snapshot of the data.
   - The `restorePVs` is set to `false` so that Velero ignores restoring PVCs.
   - The command used in the hook requires an `-operation` flag and the Velero backup name as an input.
   - The `pre-hook` will perform the steps required to bootstrap the OpenSearch cluster before invoking the OpenSearch APIs.
   - The `postHook` will invoke the OpenSearch APIs that restore the snapshot data.
   - The container on which the hook needs to be run defaults to the first container in the pod.
     In this case, it's `statefulset.kubernetes.io/pod-name: vmi-system-es-master-0`.

   **NOTE**: The hook needs to be a `postHook` because it must be applied after the Kubernetes objects are restored.

4. Wait for all the OpenSearch pods to be in the `RUNNING` state.
{{< clipboard >}}
 ```shell
   $ kubectl wait -n verrazzano-logging --for=condition=ready pod -l opster.io/opensearch-cluster=opensearch --timeout=600s
     pod/opensearch-es-data-0 condition met
     pod/opensearch-es-data-1 condition met
     pod/opensearch-es-data-2 condition met
     pod/opensearch-es-ingest-0 condition met
     pod/opensearch-es-ingest-1 condition met
     pod/opensearch-es-master-0 condition met
     pod/opensearch-es-master-1 condition met
     pod/opensearch-es-master-2 condition met
   ```
{{< /clipboard >}}

After the restore operation is processed, you can see the hook logs using the `velero restore logs` command. Additionally, the hook logs are stored under the `/tmp` folder in the pod.


<details>
  <summary>OpenSearch restore logs</summary></summary>
{{< clipboard >}}

```shell
# To display the logs from the restore, run the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero

# Fetch the log file name as shown
$ kubectl exec -it opensearch-es-master-0 -n verrazzano-logging -- ls -al /tmp | grep verrazzano-restore-hook | tail -n 1 | awk '{print $NF}'

# To examine the hook logs, exec into the pod as shown, and use the file name retrieved previously
$ kubectl exec -it opensearch-es-master-0 -n verrazzano-logging -- cat /tmp/<log-file-name>

```
{{< /clipboard >}}
</details>

## OpenSearch restore in an existing cluster using OpenSearch API

[OpenSearch restore using Velero](#opensearch-restore-using-velero) typically is used for disaster recovery scenarios where you need to restore the entire cluster. But, if you want to restore the OpenSearch data within an already existing cluster, then you can use the OpenSearch API.

Assuming that you have previously created a backup using Velero, within the same cluster that would have completed the repository registration, and want to solely restore the OpenSearch data from that specific backup, run the following commands.

To get the registered repositories:
{{< clipboard >}}
```yaml
# To see all snapshot repositories
$ GET _snapshot/_all
```
{{< /clipboard >}}

To get all the snapshots in the registered repository:
{{< clipboard >}}
```yaml
# To see all snapshots in a repository
$ GET _snapshot/<backup_repository_name>/_all
```
{{< /clipboard >}}

To restore the specific snapshot:
{{< clipboard >}}
```yaml
# To restore the existing snapshot, run the following command
$ POST _snapshot/<backup_repository_name>/<snapshot-name>/_restore
```
{{< /clipboard >}}

- `<backup_repository_name>`: The name of the backup repository where your OpenSearch snapshot is stored. Replace `<backup_repository_name>` with the name of your backup repository.

- `<snapshot-name>`: The name of the OpenSearch snapshot you want to restore. Replace `<snapshot-name>` with the name of your snapshot.

For more information, see [OpenSearch Restore](https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/#restore-snapshots) in the OpenSearch documentation.
