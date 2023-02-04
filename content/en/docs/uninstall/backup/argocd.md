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

If you created applications with resources running in different namespaces, other than `argocd`, then based on the following criteria you can backup and restore Argo CD:
- If applications running in different namespaces use persistent volumes, then you can back up the namespace where the applications are running with the PV.
- If applications running in different namespaces *do not* use persistent storage then:
<br> a) Take a backup of all the namespaces where the application is running by specifying the namespaces as a list.
<br> b) Take a backup of only the `argocd` namespace, create all the namespaces of different applications, and then restore from the backup.

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
    - argocd
    defaultVolumesToRestic: false
    storageLocation:  verrazzano-backup-location
EOF
```
{{< /clipboard >}}

The preceding example backs up the Argo CD components:
- The `defaultVolumesToRestic` is set to `false` so that Velero ignores the associated PVCs.
- If the deployed applications refer to a database or persistent volumes, then you need to manually create a backup.

<details>
  <summary>Argo CD backup logs</summary></summary>
{{< clipboard >}}

```shell
# To display the logs from the backup, run the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero
```
{{< /clipboard >}}
</details>

<br>

### Argo CD scheduled backups

Velero supports a `Schedule` [API](https://velero.io/docs/v1.8/api-types/schedule/)
that is a repeatable request that is sent to the Velero server to perform a backup for a given cron notation.
After the `Schedule` object is created, the Velero server will start the backup process.
Then, it will wait for the next valid point in the given cron expression and run the backup process on a repeating basis.

## Argo CD restore using Velero

To initiate an Argo CD restore operation, first delete the existing Argo CD cluster running on the system and all related data.

1. Delete the Argo CD components.
{{< clipboard >}}
 ```shell
# These are sample commands to demonstrate the Argo CD restore process
$ kubectl delete sts -n argocd
$ kubectl delete deploy -n argocd $ kubectl delete pvc -n argocd
 ```
{{< /clipboard >}}

2. To perform an Argo CD restore operation, you can invoke the following example Velero `Restore` [API](https://velero.io/docs/v1.8/api-types/restore/) object.
<br><br>
**NOTE:** For ArgoCD, `includedNamespaces` should list all the namespaces across which the applications are deployed.
<br>
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
     - argocd
  EOF
   ```
{{< /clipboard >}}

   The preceding example will restore an Argo CD cluster from an existing backup.

3. Wait for all the Argo CD pods to be in the `RUNNING` state.
{{< clipboard >}}
 ```shell
   $ kubectl wait -n argocd --for=condition=ready pod -l app.kubernetes.io/instance=argocd
     pod/argocd-application-controller-0 condition met
     pod/argocd-applicationset-controller-8489bfbb8-4f686 condition met
     pod/argocd-notifications-controller-c4f5c9684-8qzl8 condition met
     pod/argocd-redis-548968fdd9-4jcrf condition met
     pod/argocd-repo-server-5889c8cc68-5n8j6 condition met
     pod/argocd-server-67b6994987-j9z99 condition met
   ```
{{< /clipboard >}}

<details>
  <summary>Argo CD restore logs</summary></summary>
{{< clipboard >}}

```shell
# To display the logs from the restore, run the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero
```
{{< /clipboard >}}
</details>
