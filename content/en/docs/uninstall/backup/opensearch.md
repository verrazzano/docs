---
title: "OpenSearch Backup and Restore"
description: "Backing up and restoring Opensearch."
linkTitle: OpenSearch Backup and Restore
weight: 2
draft: false
---

When OpenSearch is deployed as part of Verrazzano, there are several PVCs created that store all the logs that are sent to OpenSearch. There are scenarios where users 
may want to back up their OpenSearch data and restore them as well. 

Verrazzano leverages `velero` to facilitate backing up and restore OpenSearch data.

- [Velero Operator prerequisites](#velero-operator-prerequisites)
- [OpenSearch Backup using Velero](#opensearch-backup-using-velero)
- [OpenSearch Restore using Velero](#opensearch-restore-using-velero)


## Velero Operator prerequisites

The following details should be kept handy before proceeding with OpenSearch back up or restore.

- Object store bucket name.
    - Both components require an object store that is Amazon S3 compatible, therefore, you need to have an object storage bucket.  This can be an Oracle Cloud Object Storage bucket in any compartment of your Oracle Cloud tenancy.
        - Make a note of the bucket name and tenancy name for reference.
        - For more information about creating a bucket with Object Storage, see [Managing Buckets](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm).
    - For private clouds, enterprise networks, or air-gapped environments, this could be MinIO or an equivalent object store solution.
- Object store prefix name. This will be a child folder under the bucket, which the backup component creates.
- Object store region name.
- Object store signing key.
    - A signing key, which is required to authenticate with the Amazon S3 compatible object store.
        - This is an Access key or a Secret Key pair.
        - Oracle provides the Access Key that is associated with your Console user login.
        - You or your administrator generates the Customer Secret key to pair with the Access Key.
    - To create a Customer Secret key, see [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#create-secret-key).



To back up or restore OpenSearch , `velero` needs to be enabled. 

1. The following configuration shows how to enable `Velero` with a `prod` installation profile.

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
  **NOTE**: The OpenSearch back up and restore is supported only on `prod` installation profiles.

2. After they're enabled, check for Velero pods running in the `verrazzano-backup` namespace.

    ```shell
    # Sample of pods running after enabling the velero component
    
    $ kubectl get pod -n verrazzano-backup
    NAME                      READY   STATUS    RESTARTS   AGE
    restic-ndxfk              1/1     Running   0          21h
    velero-5ff8766fd4-xbn4z   1/1     Running   0          21h
    
    ```


3. Velero requires a secret to communicate to the S3 compatible object store. Hence, we create a `backup-secret.txt` file, which has the object store credentials.

   ```backup-secret.txt
   [default]
   aws_access_key_id=<object store access key>
   aws_secret_access_key=<object store secret key>
   ```

4. In the namespace `verrazzano-backup`, create a Kubernetes secret `verrazzano-backup-creds`.

   ```shell
   $ kubectl create secret generic -n <backup-namespace> <secret-name> --from-file=<key>=<full_path_to_creds_file>
   ```

   The following is an example:
   ```shell
   $ kubectl create secret generic -n verrazzano-backup verrazzano-backup-creds --from-file=cloud=backup-secret.txt
   ```

   **NOTE**: To avoid misuse of sensitive data, ensure that the `backup-secret.txt` file is deleted after the Kubernetes secret is created.

5. Create a `BackupStorageLocation` object, which the backup component will reference for subsequent backups. See the following `BackupStorageLocation` example.
   For more information, see [Backup Storage Location](https://velero.io/docs/v1.8/api-types/backupstoragelocation/) in the Velero documentation.

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

## OpenSearch Backup Using Velero

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
- In this case, you are not backing up the `PersistentVolumes` directly, rather running a hook that invokes the OpenSearch APIs to take a snapshot of the data.
- `defaultVolumesToRestic` is set to `false`, so that Velero ignores the associated PVC's
- In this case, the hook can be `pre` or `post`.
- The command used in the hook requires an `operation` flag and the Velero backup name as an input.
- The container on which the hook needs to be run is identified by the pod label selectors, followed by the container name.
  In this case, it's `statefulset.kubernetes.io/pod-name: vmi-system-es-master-0`.

After the backup is processed, you can see the hook logs using the `velero backup logs` command. Additionally, the hook logs are stored under the `/tmp` folder in the pod.

<details>
  <summary>OpenSearch backup logs</summary></summary>

```shell
# To display the logs from the backup, run the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero

# Fetch the log file name as shown
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- ls -al /tmp | grep verrazzano-backup-hook | tail -n 1 | awk '{print $NF}'

# To examine the hook logs, exec into the pod as shown, and use the file name retrieved previously
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/<log-file-name>
```
</details>

<br>

### Opensearch Scheduled backups

Velero supports a `Schedule` [API](https://velero.io/docs/v1.8/api-types/schedule/)
that is a repeatable request that is sent to the Velero server to perform a backup for a given cron notation.
After the `Schedule` object is created, the Velero server will start the backup process.
Then, it will wait for the next valid point in the given cron expression and run the backup process on a repeating basis.

<br/>

## OpenSearch Restore Using Velero

For OpenSearch, Verrazzano provides a custom hook that you can use along with Velero, to perform a restore operation.
Due to the nature of transient data handled by OpenSearch, the hook invokes OpenSearch snapshot APIs to back up and restore data streams appropriately,
thereby ensuring there is no loss of data and avoids data corruption as well.

To initiate an OpenSearch restore, first delete the existing OpenSearch cluster running on the system and all related data.

1. Scale down `Verrazzano Monitoring Operator`.

    ```shell
    $ kubectl scale deploy -n verrazzano-system verrazzano-monitoring-operator --replicas=0
    ```

2. Then, clean up the OpenSearch components.

    ```shell
    # These are sample commands to demonstrate the OpenSearch restore process

    $ kubectl delete sts -n verrazzano-system -l verrazzano-component=opensearch
    $ kubectl delete deploy -n verrazzano-system -l verrazzano-component=opensearch
    $ kubectl delete pvc -n verrazzano-system -l verrazzano-component=opensearch

    ```

3. To perform an OpenSearch restore, you can invoke the following example Velero `Restore` [API](https://velero.io/docs/v1.8/api-types/restore/) object.

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
         - verrazzano-system
       labelSelector:
         matchLabels:
           verrazzano-component: opensearch
       restorePVs: false
       hooks:
         resources:
           - name: opensearch-test
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
                     - verrazzano-opensearch-backup
                   waitTimeout: 30m
                   execTimeout: 30m
                   onError: Fail
   EOF
   ```

   The preceding example will restore an OpenSearch cluster from an existing backup.
   - In this case, you are not restoring `PersistentVolumes` directly, rather running a hook that invokes the OpenSearch APIs to restore from an existing snapshot of the data.
   - `restorePVs` is set to `false`, so that Velero ignores restoring PVC's
   - The command used in the hook requires an `operation` flag and the Velero backup name as an input.
   - The `postHook` will invoke the OpenSearch APIs that restores the snapshot data.
   - The container on which the hook needs to be run is identified by the pod label selectors, followed by the container name.
     In this case, it's `statefulset.kubernetes.io/pod-name: vmi-system-es-master-0`.

   **NOTE**: The hook needs to be a `postHook` because it must be applied after the Kubernetes objects are restored.

4. Wait for all the OpenSearch pods to be in the `RUNNING` state.

   ```shell

    $ kubectl wait -n verrazzano-system --for=condition=ready pod -l verrazzano-component=opensearch --timeout=600s
      pod/vmi-system-es-data-0-6f49bdf6f5-fc6mz condition met
      pod/vmi-system-es-data-1-8f8785994-4pr7n condition met
      pod/vmi-system-es-data-2-d5f569d98-q8p2v condition met
      pod/vmi-system-es-ingest-6ddd86b9b6-fpl6j condition met
      pod/vmi-system-es-ingest-6ddd86b9b6-jtmrh condition met
      pod/vmi-system-es-master-0 condition met
      pod/vmi-system-es-master-1 condition met
      pod/vmi-system-es-master-2 condition met
    ```

After the restore operation is processed, you can see the hook logs using the `velero restore logs` command. Additionally, the hook logs are stored under the `/tmp` folder in the pod.


<details>
  <summary>OpenSearch restore logs</summary></summary>

```shell
# To display the logs from the restore, run the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero

# Fetch the log file name as shown
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- ls -al /tmp | grep verrazzano-restore-hook | tail -n 1 | awk '{print $NF}'

# To examine the hook logs, exec into the pod as shown, and use the file name retrieved previously
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/<log-file-name>

```
</details>

