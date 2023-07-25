---
title: "Rancher"
linkTitle: Rancher
weight: 2
draft: false
aliases:
  - /docs/uninstall/backup/backup
  - /docs/uninstall/backup/restore
---

Rancher maintains many configurations, like user credentials and cluster credentials, as ConfigMaps and namespace values. The
rancher-backup Operator provides a seamless way to back up and restore Rancher installations, configuration, and data.

- [rancher-backup Operator prerequisites](#rancher-backup-operator-prerequisites)
- [Rancher backup](#rancher-backup)
- [Rancher restore](#rancher-restore)


## rancher-backup Operator prerequisites

Before proceeding with a Rancher back up or restore operation, the following details should be kept handy:

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


To back up or restore Rancher, you must first enable `rancherBackup`.

1. The following configuration shows you how to enable `rancherBackup`.
{{< clipboard >}}
 ```yaml
$ kubectl apply -f -<<EOF
  apiVersion: install.verrazzano.io/v1beta1
   kind: Verrazzano
  metadata:
     name: example-verrazzano
   spec:
    profile: dev
     components:    
      rancherBackup:
         enabled: true
EOF
  ```
{{< /clipboard >}}

2. For `rancher-backup`, the pods will be created in the `cattle-resources-system` namespace.
{{< clipboard >}}

```shell
  # Sample of pods running after enabling the rancherBackup component

  $ kubectl get pod -n cattle-resources-system
  NAME                              READY   STATUS    RESTARTS   AGE
  rancher-backup-5c4b985697-xw7md   1/1     Running   0          2d4h

  ```
{{< /clipboard >}}

3. Rancher requires a secret to communicate with the S3 compatible object store. So, in the namespace `verrazzano-backup`, create a Kubernetes secret `rancher-backup-creds`.
{{< clipboard >}}
 ```shell
  $ kubectl create secret generic -n <backup-namespace> <secret-name> --from-literal=accessKey=<accesskey> --from-literal=secretKey=<secretKey>
  ```

The following is an example:

 ```shell
  $ kubectl create secret generic -n verrazzano-backup rancher-backup-creds --from-literal=accessKey="s5VLpXwa0xNZQds4UTVV" --from-literal=secretKey="nFFpvyxpQvb0dIQovsl0"
  ```
{{< /clipboard >}}

## Rancher backup

The rancher-backup Operator creates the backup file, in `*.tar.gz` format, on the S3 compatible object store.

1. To initiate a Rancher backup, create the following example custom resource YAML file that uses an Amazon S3 compatible object store as a back end.
   The operator uses the `credentialSecretNamespace` value to determine where to look for the Amazon S3 backup secret.
{{< clipboard >}}

 ```yaml
  $ kubectl apply -f - <<EOF
    apiVersion: resources.cattle.io/v1
    kind: Backup
    metadata:
      name: <rancher-backup-name>
    spec:
      storageLocation:
        s3:
          credentialSecretName: <rancher backup credential name>
          credentialSecretNamespace: <namespace where credential object was created>
          bucketName: <object store bucket. This must be exist as noted in pre-requisites section>
          folder: <folder name. This folder will be auto created>
          region: <region name where bucket exists>
          endpoint: <object store endpoint configuration>
      resourceSetName: rancher-resource-set
EOF
  ```
{{< /clipboard >}}

**NOTE**: In Step 3. of the example in the [prerequisites](#rancher-backup-operator-prerequisites) section, you created the secret in the `verrazzano-backup` namespace.

The following is an example:

{{< clipboard >}}

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
{{< /clipboard >}}

   The `*.tar.gz` file is stored in a location configured in the `storageLocation` field.
   When the backup is complete, then the rancher-backup Operator creates a file on the S3 compatible object store.

2. You can retrieve the backed up file name, as shown:
{{< clipboard >}}
 ```shell
  $ kubectl get backups.resources.cattle.io rancher-backup-test
    NAME                 LOCATION   TYPE       LATEST-BACKUP                                                                     RESOURCESET            AGE   STATUS
    rancher-backup-test             One-time   rancher-615034-957d182d-44cb-4b81-bbe0-466900049124-2022-11-14T16-42-28Z.tar.gz   rancher-resource-set   54s   Completed
  ```
{{< /clipboard >}}

### Rancher scheduled backups

To implement scheduled Rancher backups, see [Backup Configuration](https://rancher.com/docs/rancher/v2.5/en/backups/configuration/backup-config/) in the Rancher documentation.  


## Rancher restore

During the restore operation, Rancher ensures that it recreates all the CRDs related to Rancher and configurations.
Restoring Rancher is done by creating a custom resource that indicates to `rancherBackup` to start the restore process.

1. To initiate a Rancher restore operation, create the following example custom resource YAML file.
   When a `Restore` custom resource is created, the operator accesses the backup `*.tar.gz` file specified and restores the application data from that file.
{{< clipboard >}}

 ```yaml
  $ kubectl apply -f - <<EOF
    apiVersion: resources.cattle.io/v1
    kind: Restore
    metadata:
      name: s3-restore
    spec:
      backupFilename: rancher-615034-957d182d-44cb-4b81-bbe0-466900049124-2022-11-14T16-42-28Z.tar.gz
      storageLocation:
        s3:
          credentialSecretName: rancher-backup-creds
          credentialSecretNamespace: verrazzano-backup
          bucketName: myvz-bucket
          folder: rancher-backup
          region: us-phoenix-1
          endpoint: mytenancy.compat.objectstorage.us-phoenix-1.oraclecloud.com
EOF
   ```
{{< /clipboard >}}
   The rancher-backup Operator scales down the Rancher deployment during the restore operation and scales it back up after the restoration completes.

   Resources are restored in this order:
   1. Custom Resource Definitions (CRDs)
   2. Cluster-scoped resources
   3. Namespace resources

   **NOTE**: The `backupFilename` is retrieved from the Rancher backup created previously.

2. Wait for all the Rancher pods to be in the `RUNNING` state.
{{< clipboard >}}
 ```shell
 $ kubectl wait -n cattle-system --for=condition=ready pod -l app=rancher --timeout=600s
   pod/rancher-69976cffc6-bbx4p condition met
   pod/rancher-69976cffc6-fr75t condition met
   pod/rancher-69976cffc6-pcdf2 condition met
   ```
{{< /clipboard >}}
