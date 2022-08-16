---
title: "Prerequisites"
description: "Backup and restore prerequisite requirements"
linkTitle: Prerequisites
weight: 1
draft: false
---

Verrazzano provides [Velero](https://velero.io/docs/v1.8/) and [rancher-backup](https://rancher.com/docs/rancher/v2.5/en/backups/) for backup and recovery at the component and platform level. Use the following instructions to enable and configure these components in your environment.

**NOTE**:  The backup functionality requires that you install Verrazzano using the `prod` (default) profile.

## Enable backup components

To back up and restore persistent data, first you must enable the `velero` and `rancherBackup` components.
The following configuration shows how to enable the backup components with a `prod` installation profile.

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: prod
  environmentName: default
  components:    
    velero:
      enabled: true
    rancherBackup:
      enabled: true  
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
     - For more information about creating a bucket with Object Storage, refer to this [page](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm#usingconsole).
  - For private clouds, enterprise networks, or air-gapped environments, this could be MinIO or an equivalent object store solution.

- Object store prefix name. This will be a child folder under the bucket, which the backup component creates.

- Object store region information.

- A signing key, which is required to authenticate with the Amazon S3 compatible object store. Follow these steps to create a [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#Working2).




<details>
  <summary>Velero CLI (optional)</summary>

The Velero CLI helps you access Velero objects in a more descriptive manner; you can also manage them using `kubectl`.

If desired, install the Velero CLI on Oracle Linux as follows:
```shell
$ rpm -ivh https://yum.oracle.com/repo/OracleLinux/OL7/developer/olcne/x86_64/getPackage/velero-1.8.1-1.el7.x86_64.rpm
```
</details>


## Component-specific prerequisites

{{< tabs tabTotal="2" >}}
{{< tab tabName="velero" >}}
<br>

#### Velero operator prerequisites

Now, create the following objects:

- Create a `backup-secret.txt` file, which has the object store credentials.

   ```backup-secret.txt
   [default]
   aws_access_key_id=<object store access key>
   aws_secret_access_key=<object store secret key>
   ```

- In the namespace `verrazzano-backup`, create a Kubernetes secret `verrazzano-backup-creds`.

   ```shell
   $ kubectl create secret generic -n <backup-namespace> <secret-name> --from-file=<key>=<full_path_to_creds_file>
   ```

   #### Example
   ```shell
   $ kubectl create secret generic -n verrazzano-backup verrazzano-backup-creds --from-file=cloud=backup-secret.txt
   ```


   **NOTE**: To avoid misuse of sensitive data, ensure that the `backup-secret.txt` file is deleted after the Kubernetes secret is created.

- Create `BackupStorageLocation`, which the backup component will reference for subsequent backups. See the following `BackupStorageLocation` example.
  For more information, see [here](https://velero.io/docs/v1.8/api-types/backupstoragelocation/).

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

<br/>

{{< /tab >}}
{{< tab tabName="rancherBackup" >}}
<br>

#### rancher-backup operator prerequisites

Now, in the namespace `verrazzano-backup`, create a Kubernetes secret `rancher-backup-creds`.

```shell
$ kubectl create secret generic -n <backup-namespace> <secret-name> --from-literal=accessKey=<accesskey> --from-literal=secretKey=<secretKey>
```

#### Example
```shell
$ kubectl create secret generic -n verrazzano-backup rancher-backup-creds --from-literal=accessKey="s5VLpXwa0xNZQds4UTVV" --from-literal=secretKey="nFFpvyxpQvb0dIQovsl0"
```


<br/>
