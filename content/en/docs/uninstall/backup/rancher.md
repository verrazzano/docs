---
title: "Rancher Backup and Restore"
description: "Backing up and restoring Rancher."
linkTitle: Rancher Backup and Restore
weight: 2
draft: false
---

Rancher maintains a lot of configurations like user credentials, cluster creds in the form of various configmaps and namespace values. The rancher `
backup-restore-operator` provides a seamless way to back up and restore Rancher installations, configuration and data. 

- [Rancher Backup Operator prerequisites](#rancher-backup-operator-prerequisites)
- [Rancher Backup](#rancher-backup)
- [Rancher Restore](#rancher-restore)


## Rancher Backup Operator prerequisites

The following details should be kept handy before proceeding with Rancher back up or restore.

- Object store bucket name.
    - An Amazon S3 compatible object storage bucket. This can be an Oracle Cloud Object Storage bucket in any compartment of your Oracle Cloud tenancy.
        - Make a note of the bucket name and tenancy name for reference.
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


To back up or restore Rancher , `rancherBackup` needs to be enabled.

1. The following configuration shows how to enable `rancherBackup`.

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

2. For rancher-backup, the pods will be created in the `cattle-resources-system` namespace.

    ```shell
    # Sample of pods running after enabling the rancherBackup component
    
    $ kubectl get pod -n cattle-resources-system
    NAME                              READY   STATUS    RESTARTS   AGE
    rancher-backup-5c4b985697-xw7md   1/1     Running   0          2d4h
    
    ```
   
3. Rancher requires a secret to communicate to the S3 compatible object store. Hence, in the namespace `verrazzano-backup`, create a Kubernetes secret `rancher-backup-creds`.

    ```shell
    $ kubectl create secret generic -n <backup-namespace> <secret-name> --from-literal=accessKey=<accesskey> --from-literal=secretKey=<secretKey>
    ```
    
    The following is an example:
    ```shell
    $ kubectl create secret generic -n verrazzano-backup rancher-backup-creds --from-literal=accessKey="s5VLpXwa0xNZQds4UTVV" --from-literal=secretKey="nFFpvyxpQvb0dIQovsl0"
    ```


## Rancher Backup

The Rancher backup operator creates the backup file, in the `*.tar.gz` format on the S3 Compatible Object store.

1. To initiate a Rancher backup, create the following example custom resource YAML file that uses an Amazon S3 compatible object store as a backend.
   The operator uses the `credentialSecretNamespace` value to determine where to look for the Amazon S3 backup secret.

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
    
    **NOTE:** In the [prerequisites example](#rancher-backup-operator-prerequisites) example, you previously created the secret in the `verrazzano-backup` namespace.

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

    The `*.tar.gz` file is stored in location configured in the `storageLocation` field. 
    When the backup is complete, then the rancher-backup operator creates a file on the S3 Compatible Object store.

2. You can retrieve the backed up file name as shown:
    
    ```shell
    $ kubectl get backups.resources.cattle.io rancher-backup-test
    NAME                 LOCATION   TYPE       LATEST-BACKUP                                                                     RESOURCESET            AGE   STATUS
    rancher-backup-test             One-time   rancher-615034-957d182d-44cb-4b81-bbe0-466900049124-2022-11-14T16-42-28Z.tar.gz   rancher-resource-set   54s   Completed
    ```

### Rancher Scheduled backups

rancher-backup implements scheduled backups as documented [here](https://rancher.com/docs/rancher/v2.5/en/backups/configuration/backup-config/).  


## Rancher Restore

During restore, Rancher ensures it recreates all the CRD's related to Rancher and configurations as well.
Restoring Rancher is done by creating a custom resource that indicates to `rancherBackup` to start the restore process.

1. To initiate a Rancher restore, create the following example custom resource YAML file.
   When a `Restore` custom resource is created, the operator accesses the backup `*.tar.gz` file specified and restores the application data from that file.


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

   The rancher-backup operator scales down the Rancher deployment during the restore operation and scales it back up after the restoration completes.

   Resources are restored in this order:
   - Custom Resource Definitions (CRDs)
   - Cluster-scoped resources
   - Namespace resources

   **NOTE:** The `backupFilename` is retrieved from the Rancher backup created previously.

2. Wait for all the Rancher pods to be in the `RUNNING` state.

   ```shell

    $ kubectl wait -n cattle-system --for=condition=ready pod -l app=rancher --timeout=600s
      pod/rancher-69976cffc6-bbx4p condition met
      pod/rancher-69976cffc6-fr75t condition met
      pod/rancher-69976cffc6-pcdf2 condition met
    ```
