---
title: "Prerequisites"
description: "Backup and restore prerequisite requirements"
linkTitle: Prerequisites
weight: 1
draft: false
---

Verrazzano provides [Velero](https://velero.io/docs/v1.8/) and [rancher-backup](https://rancher.com/docs/rancher/v2.5/en/backups/) for backup and recovery at the component and platform level. Verrazzano also incorporates [MySQL Operator](https://dev.mysql.com/doc/mysql-operator/en/) to perform MySQL backup and restore operations. Use the following instructions to enable and configure these components in your environment.

## Enable backup components

To back up and restore persistent data, first you must enable the `velero` and `rancherBackup` components.
The following configuration shows how to enable the backup components with a `prod` installation profile.

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
      rancherBackup:
        enabled: true
EOF
```
**NOTE**: `rancherBackup` will be enabled only in cases when `rancher` is also enabled.

After they're enabled, check for Velero pods running in the `verrazzano-backup` namespace.

```shell
# Sample of pods running after enabling the velero component

$ kubectl get pod -n verrazzano-backup
NAME                      READY   STATUS    RESTARTS   AGE
restic-ndxfk              1/1     Running   0          21h
velero-5ff8766fd4-xbn4z   1/1     Running   0          21h

```
For rancher-backup, the pods will be created in the `cattle-resources-system` namespace.

```shell
# Sample of pods running after enabling the rancherBackup component

$ kubectl get pod -n cattle-resources-system
NAME                              READY   STATUS    RESTARTS   AGE
rancher-backup-5c4b985697-xw7md   1/1     Running   0          2d4h

```

## Configure backup components

Next, meet the following prerequisite requirements for both `velero` and `rancherBackup` components:

- Object store bucket name.
  - Both components require an object store that is Amazon S3 compatible, therefore, you need to have an object storage bucket.  This can be an Oracle Cloud Object Storage bucket in any compartment of your Oracle Cloud tenancy.
     - Make a note of the bucket name and tenancy name for reference.
     - For more information about creating a bucket with Object Storage, see [Managing Buckets](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm).
  - For private clouds, enterprise networks, or air-gapped environments, this could be MinIO or an equivalent object store solution.

- Object store prefix name. This will be a child folder under the bucket, which the backup component creates.

- Object store region information.

- A signing key, which is required to authenticate with the Amazon S3 compatible object store. This special signing key is an Access Key/Secret Key pair.
  Oracle provides the Access Key that is associated with your Console user login. You or your administrator generates the Customer Secret key to pair with the Access Key. 
  Follow these steps to create a [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#create-secret-key).

- MySQL Operator uses OCI credentials to back up and restore MySQL data. Hence, OCI credentials will also be needed before configuring MySQL backup or restore.



<details>
  <summary>Velero CLI (optional)</summary>

The Velero CLI helps you access Velero objects in a more descriptive manner; you can also manage them using `kubectl`.

If desired, install the Velero CLI on Oracle Linux as follows:
```shell
$ rpm -ivh https://yum.oracle.com/repo/OracleLinux/OL7/developer/olcne/x86_64/getPackage/velero-1.8.1-1.el7.x86_64.rpm
```
</details>


## Component-specific prerequisites

Meet the following component-specific prerequisites:

- [Velero operator prerequisites](#velero-operator-prerequisites)
- [rancher-backup operator prerequisites](#rancher-backup-operator-prerequisites)
- [MySQL Operator prerequisites](#mysql-operator-prerequisites)

#### Velero operator prerequisites

Now, create the following objects:

1. Create a `backup-secret.txt` file, which has the object store credentials.

   ```backup-secret.txt
   [default]
   aws_access_key_id=<object store access key>
   aws_secret_access_key=<object store secret key>
   ```

2. In the namespace `verrazzano-backup`, create a Kubernetes secret `verrazzano-backup-creds`.

   ```shell
   $ kubectl create secret generic -n <backup-namespace> <secret-name> --from-file=<key>=<full_path_to_creds_file>
   ```

   The following is an example:
   ```shell
   $ kubectl create secret generic -n verrazzano-backup verrazzano-backup-creds --from-file=cloud=backup-secret.txt
   ```


   **NOTE**: To avoid misuse of sensitive data, ensure that the `backup-secret.txt` file is deleted after the Kubernetes secret is created.

3. Create `BackupStorageLocation`, which the backup component will reference for subsequent backups. See the following `BackupStorageLocation` example.
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

#### rancher-backup operator prerequisites

Now, in the namespace `verrazzano-backup`, create a Kubernetes secret `rancher-backup-creds`.

```shell
$ kubectl create secret generic -n <backup-namespace> <secret-name> --from-literal=accessKey=<accesskey> --from-literal=secretKey=<secretKey>
```

The following is an example:
```shell
$ kubectl create secret generic -n verrazzano-backup rancher-backup-creds --from-literal=accessKey="s5VLpXwa0xNZQds4UTVV" --from-literal=secretKey="nFFpvyxpQvb0dIQovsl0"
```

#### MySQL Operator prerequisites

Prior to starting a MySQL backup or restore, the MySQL Operator requires that the following secret exists.
The following example creates a secret `mysql-backup-secret` in the namespace `keycloak`.

**NOTE:**  This secret must exist in the namespace `keycloak`.

````shell
$ kubectl create secret generic -n keycloak  <secret-name> \
        --from-literal=user=<oci user id> \
        --from-literal=fingerprint=<oci user fingerprint> \
        --from-literal=tenancy=<oci tenancy id>> \
        --from-literal=region=<region where bucket is created> \
        --from-literal=passphrase="" \
        --from-file=privatekey=<full path to private key pem file>
````

The following is an example:

````shell
$ kubectl create secret generic -n keycloak  mysql-backup-secret \
        --from-literal=user=ocid1.user.oc1..aaaaaaaa \
        --from-literal=fingerprint=aa:bb:cc:dd:ee:ff \
        --from-literal=tenancy=ocid1.tenancy.oc1..bbbbbbbbb \
        --from-literal=region=us-phoenix-1 \
        --from-literal=passphrase="" \
        --from-file=privatekey=/tmp/key.pem
````
