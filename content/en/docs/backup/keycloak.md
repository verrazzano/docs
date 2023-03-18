---
title: "Keycloak Backup and Restore"
description: "Back up and restore Keycloak data"
linkTitle: Keycloak Backup and Restore
weight: 2
draft: false
---

Verrazzano stores user login information in Keycloak. In turn, Keycloak uses MySQL as a back end to store all persistent data.
This document shows you how to back up and restore data stored in MySQL.

- [MySQL Operator prerequisites](#mysql-operator-prerequisites)
- [MySQL Operator backup](#mysql-operator-backup)
- [MySQL Operator restore](#mysql-operator-restore)

## MySQL Operator prerequisites

MySQL is deployed using the [MySQL Operator for Kubernetes](https://dev.mysql.com/doc/mysql-operator/en/). Apart from managing the life cycle of MySQL instances, MySQL Operator provides the capability to back up and restore data using an OCI object store.

Before proceeding with a MySQL back up or restore operation, keep the following details handy:

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


The following example creates a secret `mysql-backup-secret` in the namespace `keycloak`.

**NOTE**:  This secret must exist in the namespace `keycloak`.
{{< clipboard >}}

1. MySQL Operator requires a secret to communicate with the S3 compatible object store, so we create a `backup-secret.txt` file, which has the object store credentials.

   ```backup-secret.txt
   [default]
   aws_access_key_id=<object store access key>
   aws_secret_access_key=<object store secret key>
   ```

2. MySQL Operator requires the region name where the bucket is created, so we create a `backup-region.txt` file, which contains the region information.

   ```backup-region.txt
   [default]
   region=us-phoenix-1
   ```

3. In the namespace `keycloak`, create a Kubernetes secret, for example `mysql-backup-secret`.

   ```shell
   $ kubectl create secret generic -n <backup-namespace> <secret-name> --from-file=<key>=<full_path_to_creds_file> --from-file=<key>=<full_path_to_config_file>
   ```

   The following is an example of creating a Kubernetes secret consisting of OCI credentials.
   ```shell
   $ kubectl create secret generic -n keycloak mysql-backup-secret --from-file=credentials=backup-secret.txt --from-file=config=backup-region.txt
   ```

   **NOTE**: To avoid misuse of sensitive data, ensure that the `backup-secret.txt` file is deleted after the Kubernetes secret is created.


## MySQL Operator backup

To initiate a MySQL backup, create the following example custom resource YAML file that uses an OCI object store as a back end.
The operator uses the secret referenced in `spec.backupProfile.dumpInstance.storage.s3.config` to authenticate with the OCI object store.

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
          s3:
             bucketName: <The Object store bucket. See the MySQL Operator prerequisites section.>
             config: <Kubernetes secret name. See the MySQL Operator prerequisites section.>
             endpoint: < OCI S3 object store endpoint. >
             prefix: <The prefix name. This folder will be automatically created.>
             profile: default
EOF
```

**NOTE**:
- The `config` value is `mysql-backup-secret`, which is the name of the secret that you created previously in the `keycloak` namespace.
- The `clustername` has to be `mysql`.
- The `namespace` has to be `keycloak`.
- The `profile` value is the profile for the security credentials. In this case, it is `default`.

The following is an example of a `MySQLBackup` resource to initiate a MySQL backup:

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
          s3:
             bucketName: mysql-bucket
             config: mysql-backup-secret
             endpoint: https://mytenancy.compat.objectstorage.us-phoenix-1.oraclecloud.com
             prefix: mysql-test
             profile: default  
EOF
```

### Scheduled backups

You can also implement schedules for running MYSQL backups. For more information, see [Handling MySQL Backups](https://dev.mysql.com/doc/mysql-operator/en/mysql-operator-backups.html),
A PersistentVolumeClaim Scheduled Backup Example, under `backupSchedules`.

## MySQL Operator restore

Before you begin, read the [MySQL Operator prerequisites](#mysql-operator-prerequisites). In addition, you must have at least one healthy backup before starting a restore operation.

To initiate a MySQL restore operation from an existing backup, you need to recreate the MySQL cluster. Use the following steps for a successful MySQL restore operation:

1. Back up the values in the MySQL Helm chart to a file, `mysql-values.yaml`.

   ```shell
    $ helm get values -n keycloak mysql > mysql-values.yaml
    ```

2. The MySQL backup creates a backup folder in the object store. Get the backup folder prefix name that the MySQL backup created.

    ```shell
    $ kubectl get mysqlbackup -n keycloak <mysql-backup-name> -o jsonpath={.status.output}
    ```
   The following is an example:
    ```shell
    $ kubectl get mysqlbackup -n keycloak mysql-backup -o jsonpath={.status.output}
    mysql-backup-20221025-180836
    ```

3. Typically, the MySQL Helm charts are present inside the Verrazzano platform operator. Retrieve the charts to a local directory called `mysql-charts`.

    ```shell
    $ mkdir mysql-charts
    $ kubectl cp -n verrazzano-install \
        $(kubectl get pod -n verrazzano-install -l app=verrazzano-platform-operator \
        -o custom-columns=:metadata.name --no-headers):platform-operator/thirdparty/charts/mysql \
        -c verrazzano-platform-operator mysql-charts/
    ```

4. Delete the MySQL pods and PVC from the system.

    ```shell
    $ helm delete mysql -n keycloak
    $ kubectl delete pvc -n keycloak -l tier=mysql
    ```

5. Now that you have removed MySQL from the system, trigger a MySQL restore operation by installing the Helm chart as follows.

    ```shell
    $ helm install mysql mysql-charts \
            --namespace keycloak \
            --set initDB.dump.name=<dump-name> \
            --set initDB.dumpOptions.loadUsers=true \
            --set initDB.dump.s3.profile=default \
            --set initDB.dump.s3.prefix=<prefixName/backup folder name> \
            --set initDB.dump.s3.bucketName=<OCI bucket name> \
            --set initDB.dump.s3.config=<Credential Name> \
            --set initDB.dump.s3.endpoint=<OCI S3 endpoint> \
            --values <mysql values file>
   ```

   The following is an example:

    ```shell
    $ helm install mysql mysql-charts \
            --namespace keycloak \
            --set initDB.dump.name=alpha \
            --set initDB.dump.s3.profile=default \
            --set initDB.dump.s3.prefix=mysql-test/mysql-backup-20221025-180836 \
            --set initDB.dump.s3.bucketName=mysql-bucket \
            --set initDB.dump.s3.config=mysql-backup-secret \
            --set initDB.dump.s3.endpoint=https://mytenancy.compat.objectstorage.us-phoenix-1.oraclecloud.com \
            --values mysql-values.yaml
    ```

6. After performing the restore command, wait for the MySQL cluster to be online. Ensure that the `STATUS` is `ONLINE` and the count under `ONLINE` matches the `INSTANCES`.

   ```shell
    $ kubectl get innodbclusters -n keycloak mysql
      NAME    STATUS   ONLINE   INSTANCES   ROUTERS   AGE
      mysql   ONLINE   3        3           3         2m23s
    ```

7. Wait for all the MySQL pods to be in the `RUNNING` state.

   ```shell
    $ kubectl wait -n keycloak --for=condition=ready pod -l tier=mysql --timeout=600s
      pod/mysql-0 condition met
      pod/mysql-1 condition met
      pod/mysql-2 condition met
      pod/mysql-router-746d9d75c7-6pc5p condition met
      pod/mysql-router-746d9d75c7-bhrkw condition met
      pod/mysql-router-746d9d75c7-t8bhb condition met
    ```

At this point, the MySQL cluster has been restored successfully from the backup, along with the PVCs that were deleted previously.

The removal and recreation of the MySQL cluster may cause the Keycloak pods to go into a crashloop state because MySQL goes offline during the restore operation.
Keycloak is set up to self-heal and will go into a `Running` state after all the back ends are available. You may also choose to force Keycloak into a `Running` state by using the following commands:

```shell
KEYCLOAK_REPLICAS=$(kubectl get sts -n keycloak keycloak -o custom-columns=:status.replicas --no-headers)
kubectl scale sts -n keycloak keycloak --replicas=0
kubectl scale sts -n keycloak keycloak --replicas=${KEYCLOAK_REPLICAS}
kubectl wait -n keycloak --for=condition=ready pod -l app.kubernetes.io/instance=keycloak -timeout=600s
```
**NOTE**:  If you are restoring the Keycloak on a different cluster, then make sure that the following secrets in the
`verrazzano-system` namespace are updated in the new cluster with the corresponding values from the
original cluster:
- verrazzano
- verrazzano-es-internal
- verrazzano-prom-internal

Also, restart the `fluentd` pods in the new cluster to use the original cluster password to connect to OpenSearch.
```
$ kubectl delete pod -l app=fluentd -n verrazzano-system
```
         
{{< /clipboard >}}
