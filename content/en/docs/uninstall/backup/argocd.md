---
title: "Argo CD Backup and Restore"
description: "Back up and restore Argo CD"
linkTitle: Argo CD Backup and Restore
weight: 2
draft: false
---

Verrazzano provides a ready-to-use, Argo CD deployment that automates the deployment of the desired application states in the specified target environments.
There are scenarios where you may want to back up your Argo CD data and restore it.

Verrazzano uses Velero to facilitate backing up and restoring Argo CD data.

- [Velero operator prerequisites](#velero-operator-prerequisites)
- [Argo CD backup using Velero](#argo-cd-backup-using-velero)
- [Argo CD restore using Velero](#argo-cd-restore-using-velero)


## Velero operator prerequisites

Before proceeding with an Argo CD backup or restore operation, the following details should be kept handy:

- Object store bucket name.
    - An Amazon S3 compatible object storage bucket. This can be an Oracle Cloud Object Storage bucket in any compartment of your Oracle Cloud tenancy.
        - For reference, make a note of the bucket name and tenancy name.
        - For more information about creating a bucket with Object Storage, see [Managing Buckets](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm).
    - For private clouds, enterprise networks, or air-gapped environments, this could be MinIO or an equivalent object store solution.
- Object store prefix name. This will be a child folder under the bucket, which the backup component creates.
- Object store region name.
- Object store signing key.
    - A signing key, which is required to authenticate with the Amazon S3 compatible object store.
        - This is an Access Key or a Secret Key pair.
        - Oracle provides the Access Key that is associated with your Console user login.
        - You or your administrator generates the Customer Secret Key to pair with the Access Key.
    - To create a Customer Secret Key, see [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#create-secret-key).



To back up or restore Argo CD, you must first enable Velero.

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

  **NOTE**: The Argo CD back up and restore operation is supported _only_ on `prod` installation profiles with a multinode Argo CD configuration.

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
   For more information, see [Backup Storage Location](https://velero.io/docs/v1.8/api-types/backupstoragelocation/#backup-storage-location) in the Velero documentation.
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
## Argo CD backup using Velero

For Argo CD, Verrazzano provides a custom hook that you can use along with Velero while invoking a backup.
Due to the nature of transient data handled by Argo CD, the hook invokes the Argo CD snapshot APIs to back up data streams appropriately,
thereby ensuring that there is no loss of data and avoids data corruption as well.

**NOTE:** For ArgoCD, `includedNamespaces` should list all the namespaces across which the applications are deployed.

The following example shows a sample Velero `Backup` [API](https://velero.io/docs/v1.8/api-types/backup/) resource that you can create to initiate an Argo CD backup.
{{< clipboard >}}

```yaml
$ kubectl apply -f - <<EOF
  apiVersion: velero.io/v1
  kind: Backup
  metadata:
    name: verrazzano-argocd-backup
    namespace: verrazzano-backup
  spec:
    includedNamespaces:
      - verrazzano-system
    labelSelector:
      matchLabels:
        verrazzano-component: argocd
    defaultVolumesToRestic: false
    storageLocation:  verrazzano-backup-location
    hooks:
      resources:
        - name: argocd-backup-test
          includedNamespaces:
            - verrazzano-system
          labelSelector:
            matchLabels:
              statefulset.kubernetes.io/pod-name: vmi-system-es-master-0
          post:                           
            - exec:
                container: es-master
                command:
                  - /usr/share/argocd/bin/verrazzano-backup-hook
                  - -operation
                  - backup
                  - -velero-backup-name
                  - verrazzano-argocd-backup
                onError: Fail
                timeout: 10m
EOF
```
{{< /clipboard >}}

The preceding example backs up the Argo CD components:
- In this case, you are not backing up the `PersistentVolumes` directly, rather running a hook that invokes the Argo CD APIs to take a snapshot of the data.
- The `defaultVolumesToRestic` is set to `false` so that Velero ignores the associated PVCs.
- In this case, the hook can be `pre` or `post`.
- The command used in the hook requires an `operation` flag and the Velero backup name as an input.
- The container on which the hook needs to be run defaults to the first container in the pod.
  In this case, it's `statefulset.kubernetes.io/pod-name: vmi-system-es-master-0`.

After the backup is processed, you can see the hook logs using the `velero backup logs` command. Additionally, the hook logs are stored under the `/tmp` folder in the pod.

<details>
  <summary>Argo CD backup logs</summary></summary>
{{< clipboard >}}

```shell
# To display the logs from the backup, run the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero

# Fetch the log file name as shown
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- ls -al /tmp | grep verrazzano-backup-hook | tail -n 1 | awk '{print $NF}'

# To examine the hook logs, exec into the pod as shown, and use the file name retrieved previously
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/<log-file-name>
```
{{< /clipboard >}}
</details>

<br>

### Argo CD scheduled backups

Velero supports a `Schedule` [API](https://velero.io/docs/v1.8/api-types/schedule/)
that is a repeatable request that is sent to the Velero server to perform a backup for a given cron notation.
After the `Schedule` object is created, the Velero server will start the backup process.
Then, it will wait for the next valid point in the given cron expression and run the backup process on a repeating basis.

<br/>

## Argo CD restore using Velero

For Argo CD, Verrazzano provides a custom hook that you can use along with Velero to perform a restore operation.
Due to the nature of transient data handled by Argo CD, the hook invokes Argo CD snapshot APIs to restore data streams appropriately,
thereby ensuring there is no loss of data and avoids data corruption as well.

To initiate an Argo CD restore operation, first delete the existing Argo CD cluster running on the system and all related data.

1. Scale down the Verrazzano Monitoring Operator. This is required because the operator manages the life cycle of the Argo CD cluster, so scaling it down to zero ensures that it does not interfere with the restore operation.
   The restore operation also ensures that this operator is scaled back up to return the system to its previous state.
{{< clipboard >}}
 ```shell
  $ kubectl scale deploy -n verrazzano-system verrazzano-monitoring-operator --replicas=0
  ```
{{< /clipboard >}}

2. Delete the Argo CD components.
{{< clipboard >}}
 ```shell
# These are sample commands to demonstrate the Argo CD restore process
$ kubectl delete sts -n verrazzano-system -l verrazzano-component=argocd
$ kubectl delete deploy -n verrazzano-system -l verrazzano-component=argocd    $ kubectl delete pvc -n verrazzano-system -l verrazzano-component=argocd
 ```
{{< /clipboard >}}

3. To perform an Argo CD restore operation, you can invoke the following example Velero `Restore` [API](https://velero.io/docs/v1.8/api-types/restore/) object.

**NOTE:** For ArgoCD, `includedNamespaces` should list all the namespaces across which the applications are deployed.

{{< clipboard >}}
 ```yaml
  $ kubectl apply -f - <<EOF
   apiVersion: velero.io/v1
    kind: Restore
   metadata:
      name: verrazzano-argocd-restore
     namespace: verrazzano-backup
   spec:
     backupName: verrazzano-argocd-backup
     includedNamespaces:
       - verrazzano-system
      labelSelector:
        matchLabels:
          verrazzano-component: argocd
      restorePVs: false
      hooks:
        resources:
         - name: argocd-test
           includedNamespaces:
             - verrazzano-system       
           labelSelector:
              matchLabels:            
               statefulset.kubernetes.io/pod-name: vmi-system-es-master-0
           postHooks:
             - exec:
                 container: es-master
                 command:
                    - /usr/share/argocd/bin/verrazzano-backup-hook
                    - -operation
                    - restore
                    - -velero-backup-name
                    - verrazzano-argocd-backup
                 waitTimeout: 30m
                 execTimeout: 30m
                  onError: Fail
  EOF
   ```
{{< /clipboard >}}

   The preceding example will restore an Argo CD cluster from an existing backup.
   - In this case, you are not restoring `PersistentVolumes` directly, rather running a hook that invokes the Argo CD APIs to restore them from an existing snapshot of the data.
   - The `restorePVs` is set to `false` so that Velero ignores restoring PVCs.
   - The command used in the hook requires an `-operation` flag and the Velero backup name as an input.
   - The `postHook` will invoke the Argo CD APIs that restore the snapshot data.
   - The container on which the hook needs to be run defaults to the first container in the pod.
     In this case, it's `statefulset.kubernetes.io/pod-name: vmi-system-es-master-0`.

   **NOTE**: The hook needs to be a `postHook` because it must be applied after the Kubernetes objects are restored.

4. Wait for all the Argo CD pods to be in the `RUNNING` state.
{{< clipboard >}}
 ```shell
   $ kubectl wait -n verrazzano-system --for=condition=ready pod -l verrazzano-component=argocd --timeout=600s
     pod/vmi-system-es-data-0-6f49bdf6f5-fc6mz condition met
     pod/vmi-system-es-data-1-8f8785994-4pr7n condition met
     pod/vmi-system-es-data-2-d5f569d98-q8p2v condition met
     pod/vmi-system-es-ingest-6ddd86b9b6-fpl6j condition met
     pod/vmi-system-es-ingest-6ddd86b9b6-jtmrh condition met
     pod/vmi-system-es-master-0 condition met
     pod/vmi-system-es-master-1 condition met
     pod/vmi-system-es-master-2 condition met
   ```
{{< /clipboard >}}

After the restore operation is processed, you can see the hook logs using the `velero restore logs` command. Additionally, the hook logs are stored under the `/tmp` folder in the pod.


<details>
  <summary>Argo CD restore logs</summary></summary>
{{< clipboard >}}

```shell
# To display the logs from the restore, run the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero

# Fetch the log file name as shown
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- ls -al /tmp | grep verrazzano-restore-hook | tail -n 1 | awk '{print $NF}'

# To examine the hook logs, exec into the pod as shown, and use the file name retrieved previously
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/<log-file-name>

```
{{< /clipboard >}}
</details>
