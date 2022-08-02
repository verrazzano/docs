---
title: "Backup Prerequisites"
description: "Prerequisites required for performing a backup/restore"
linkTitle: Backup Prerequisites
weight: 1
draft: false
---

Verrazzano offers the following operators for backing up and restoring persistent data and configurations from the platform. 

- Velero 
- Rancher Backup Operator

Before proceeding to the next section the following information is required as input for both the operators:

- Create an Oracle Cloud Object Storage bucket in any compartment of your Oracle Cloud tenancy. Make a note of the bucket name and tenancy name for reference. Refer to this [page](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm#usingconsole) for more information about creating a bucket with Object Storage.

- Object store prefix name - this will be a child folder under the bucket automatically created by the backup component.

- Object store region information.

- Verrazzano backup component requires object store to be Amazon S3 compatible. As a result you need to generate the signing key required to authenticate with Amazon S3.
  Follow these steps to create a [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#To4).

- Ensure the appropriate components are enabled in the Verrazzano CR at the time of [install](/docs/setup/backup/installation/#backup-component-installation).
 

### Velero Operator Prerequisite

You can now create the following objects as shown here:

- Create a file `backup-secret.txt` having the object store credentials as shown below.

```backup-secret.txt
[default]
aws_access_key_id=<object store access key>
aws_secret_access_key=<object store secret key>
```

- Create a kubernetes secret `verrazzano-backup-creds` in the namespace `verrazzano-backup`.

```
kubectl create secret generic -n <backup-namespace> <secret-name> --from-file=<key>=<full_path_to_creds_file>

Example 
kubectl create secret generic -n verrazzano-backup verrazzano-backup-creds --from-file=cloud=backup-secret.txt
```

**_NOTE:_** Ensure the `backup-secret.txt` file is cleaned up after the kubernetes secret is created to avoid misuse of sensitive data.

- Create a `BackupStorageLocation` which the backup component will reference for subsequent backups. Below is an example of the `BackupStorageLocation`.
  Refer this [page](https://velero.io/docs/v1.8/api-types/backupstoragelocation/) for more information.

```yaml
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
```

### Rancher Backup Operator Prerequisite

You can now create the following objects as follows:

- Create a kubernetes secret `rancher-backup-creds` in the namespace `verrazzano-backup`.

```
kubectl create secret generic -n <backup-namespace> <secret-name> --from-literal=accessKey=<accesskey> --from-literal=secretKey=<secretKey>

Example 
kubectl create secret generic -n verrazzano-backup rancher-backup-creds --from-literal=accessKey="s5VLpXwa0xNZQds4UTVV" --from-literal=secretKey="nFFpvyxpQvb0dIQovsl0"
```

