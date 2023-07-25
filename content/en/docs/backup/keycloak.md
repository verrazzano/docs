---
title: "Keycloak"
linkTitle: Keycloak
weight: 2
draft: false
---

Verrazzano stores user login information in Keycloak. In turn, Keycloak uses MySQL as a back end to store all persistent data.
This document shows you how to back up persistent data stored in MySQL from the original cluster and restore it in a new cluster.
If you are restoring data to the same cluster, then the terms original cluster and new cluster refer to same cluster.

- [MySQL Operator prerequisites](#mysql-operator-prerequisites)
- [MySQL Operator backup](#mysql-operator-backup)
- [MySQL Operator restore](#mysql-operator-restore)


## MySQL Operator prerequisites

MySQL is deployed using the [MySQL Operator for Kubernetes](https://dev.mysql.com/doc/mysql-operator/en/). Apart from managing the life cycle of MySQL instances, MySQL Operator provides the capability to back up and restore data using an Amazon S3 compatible object storage.

Before proceeding with a MySQL back up or restore operation, keep the following details handy:

- Object storage bucket name.
   - An Amazon S3 compatible object storage bucket. This can be an Oracle Cloud Object Storage bucket in any compartment of your Oracle Cloud tenancy.
      - For reference, make a note of the bucket name and tenancy name.
      - For more information about creating a bucket with Object Storage, see [Managing Buckets](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm).
   - For private clouds, enterprise networks, or air-gapped environments, this could be MinIO or an equivalent object storage solution.
- Object storage prefix name. This will be a child folder under the bucket, which the backup component creates.
- Object storage region name.
- Object storage signing key.
   - A signing key, which is required to authenticate with the Amazon S3 compatible object storage; this is an Access Key/Secret Key pair.
   - In Oracle Cloud Infrastructure (OCI), you or your administrator creates the Customer Secret Key.
      - An associated Access Key will be generated for the secret key.
      - To create a Customer Secret Key, see [Customer Secret Key](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm#create-secret-key).

The following example creates a secret `mysql-backup-secret` in the namespace `keycloak`. The instructions in this document back up data from MySQL to an Oracle Cloud Object Storage bucket and restore it from there.

1. MySQL Operator requires a secret to communicate with the S3 compatible object storage, so we create a `backup-secret.txt` file, which has the object storage credentials.

   {{< clipboard >}}
   ```
   [default]
   aws_access_key_id=<object storage access key>
   aws_secret_access_key=<object storage secret key>
   ```
   {{< /clipboard >}}

2. MySQL Operator requires the region name where the bucket is created, so we create a `backup-region.txt` file, which contains the region information.
   The following is an example of a `backup-region.txt` file indicating that the object storage is created in region `us-phoenix-1`:
   {{< clipboard >}}
   ```
   [default]
   region=us-phoenix-1
   ```
   {{< /clipboard >}}

3. In the namespace `keycloak`, create a Kubernetes secret, for example `mysql-backup-secret`.

   {{< clipboard >}}
   ```bash
   $ kubectl create secret generic --namespace <backup-namespace> <secret-name> --from-file=<key>=<full_path_to_creds_file> --from-file=<key>=<full_path_to_config_file>
   ```
   {{< /clipboard >}}

   The following is an example to create a Kubernetes secret consisting of credentials to connect to OCI Object Storage.
   ```
   $ kubectl create secret generic --namespace keycloak mysql-backup-secret --from-file=credentials=backup-secret.txt --from-file=config=backup-region.txt
   ```

{{< alert title="NOTE" color="primary" >}}
- The secret must be created in the namespace `keycloak`.
- To restore Keycloak on a new cluster, create the secret in the namespace, `keycloak`, in the new cluster.
- To avoid misuse of sensitive data, ensure that the `backup-secret.txt` file is deleted after the Kubernetes secret is created.
{{< /alert >}}

## MySQL Operator backup

1. To initiate a MySQL backup on the original cluster, create the following example custom resource YAML file that uses an OCI Object Storage as a back end.
   The operator uses the secret referenced in `spec.backupProfile.dumpInstance.storage.s3.config` to authenticate with the OCI Object Storage.

   {{< clipboard >}}
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
                 bucketName: <The Object Storage bucket. See the MySQL Operator prerequisites section.>
                 config: <Kubernetes secret name. See the MySQL Operator prerequisites section.>
                 endpoint: < OCI S3 Object Storage endpoint.>
                 prefix: <The prefix name. This folder will be automatically created.>
                 profile: default
EOF
   ```
   {{< /clipboard >}}

   {{< alert title="NOTE" color="primary" >}}
   - The `config` value is `mysql-backup-secret`, which is the name of the secret that you created previously in the `keycloak` namespace.
   - The `clustername` has to be `mysql`.
   - The `namespace` has to be `keycloak`.
   - The `profile` value is the profile for the security credentials. In this case, it is `default`.
   {{< /alert >}}

   The following is an example of a `MySQLBackup` resource to initiate a MySQL backup:

   ```
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

2. Confirm that the backup operation is complete. Run the following command on the original cluster and ensure that the `STATUS` is `Completed`.
   {{< clipboard >}}
   ```bash
   $ kubectl get MySQLBackup --namespace keycloak
   ```
   ```
   # Sample output
   NAME           CLUSTER   STATUS      OUTPUT                         AGE
   mysql-backup   mysql     Completed   mysql-backup-20221025-180836   119s
   ```
   {{< /clipboard >}}

3. A successful backup of MySQL creates a backup folder in the object storage. Make note of the backup folder prefix name that the MySQL backup created on the original cluster.

   {{< clipboard >}}
   ```bash
   $ kubectl get mysqlbackup --namespace keycloak <mysql-backup-name> -o jsonpath={.status.output}
   ```
   {{< /clipboard >}}

   The following is an example:
   ```
   $ kubectl get mysqlbackup --namespace keycloak mysql-backup -o jsonpath={.status.output}
   mysql-backup-20221025-180836
   ```

4. Back up MySQL Helm chart and values.

   Back up the values in the MySQL Helm chart, in the original cluster to a file, `mysql-values.yaml` .

   {{< clipboard >}}
   ```bash
   $ helm get values --namespace keycloak mysql > mysql-values.yaml
   ```
   {{< /clipboard >}}

   MySQL Helm charts are present inside the Verrazzano platform operator. Retrieve the charts from the original cluster to a local directory.

   The following example retrieves the MySQL charts to a directory `mysql-charts` under the current directory. In order to avoid data corruption, ensure
that the directory, `mysql-charts`, doesn't already exist under the current directory.

   {{< clipboard >}}
   ```bash
   $ kubectl cp --namespace verrazzano-install \
       $(kubectl get pod --namespace verrazzano-install -l app=verrazzano-platform-operator \
       -o custom-columns=:metadata.name --no-headers):platform-operator/thirdparty/charts/mysql \
       -c verrazzano-platform-operator mysql-charts/
   ```
   {{< /clipboard >}}

### Scheduled backups

You can also implement schedules for running MYSQL backups. For more information, see the [Handling MySQL Backups](https://dev.mysql.com/doc/mysql-operator/en/mysql-operator-backups.html) section,
"A PersistentVolumeClaim Scheduled Backup Example."

## MySQL Operator restore

Before you begin, read the [MySQL Operator prerequisites](#mysql-operator-prerequisites). In addition, you must have at least one healthy backup before starting a restore operation.

To initiate a MySQL restore operation from an existing backup, you need to recreate the MySQL cluster. Use the following steps for a successful MySQL restore operation:

1. Delete the MySQL pods and `PersistentVolumeClaim` from the system on the new cluster.
   {{< clipboard >}}
   ```bash
   $ helm delete mysql --namespace keycloak
   $ kubectl delete pvc --namespace keycloak -l tier=mysql
   ```
   {{< /clipboard >}}

2. Start a MySQL restore operation by installing the Helm chart by using the chart from the original cluster.

   {{< clipboard >}}
   ```bash
    $ helm install mysql <path to directory mysql-charts, where original charts are extracted> \
            --namespace keycloak \
            --set initDB.dump.name=<dump-name> \
            --set initDB.dumpOptions.loadUsers=true \
            --set initDB.dump.s3.profile=default \
            --set initDB.dump.s3.prefix=<prefixName/backup folder name> \
            --set initDB.dump.s3.bucketName=<OCI bucket name> \
            --set initDB.dump.s3.config=<Kubernetes secret name, see MySQL Operator prerequisites section.> \
            --set initDB.dump.s3.endpoint=<OCI S3 endpoint> \
            --values <mysql values file>
   ```
   {{< /clipboard >}}

   The following is an example:
   ```
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

3. After performing the restore command, wait for the MySQL cluster to be online. Ensure that the `STATUS` is `ONLINE` and the count under `ONLINE` matches the `INSTANCES`.

   {{< clipboard >}}
   ```bash
   $ kubectl get innodbclusters --namespace keycloak mysql
   ```

   ```
   # Sample output
   NAME    STATUS   ONLINE   INSTANCES   ROUTERS   AGE
   mysql   ONLINE   3        3           3         2m23s
   ```
   {{< /clipboard >}}

4. Wait for all the MySQL pods to be in the `RUNNING` state.

   {{< clipboard >}}
   ```bash
   $ kubectl wait --namespace keycloak --for=condition=ready pod -l tier=mysql --timeout=600s
   ```
   ```
   # Sample output
   pod/mysql-0 condition met
   pod/mysql-1 condition met
   pod/mysql-2 condition met
   pod/mysql-router-746d9d75c7-6pc5p condition met
   pod/mysql-router-746d9d75c7-bhrkw condition met
   pod/mysql-router-746d9d75c7-t8bhb condition met
   ```
   {{< /clipboard >}}

   At this point, the MySQL cluster has been restored successfully from the backup, along with the `PersistentVolumeClaim` that was deleted previously.

5. If you are restoring Keycloak on a new cluster, then update the Keycloak secret.

   On the original cluster, if you are restoring Keycloak on a new cluster, then run the following command for the `keycloak-http` secret in `keycloak` namespace:
   {{< clipboard >}}
   ```bash
    $ kubectl get secret --namespace keycloak keycloak-http -o jsonpath={.data.password}; echo
   ```
    {{< /clipboard >}}

    On the new cluster, replace the existing password value with the value displayed from the previous command.
    {{< clipboard >}}
   ```bash
    kubectl patch secret keycloak-http --namespace keycloak -p '{"data": {"password": "<password displayed in the step above>"}}'
   ```
    {{< /clipboard >}}

6. Restart the Keycloak pods.

   The removal and recreation of the MySQL cluster may bring down the Keycloak pods because MySQL goes offline during the restore operation. Run the following commands to restart the Keycloak pods:
   {{< clipboard >}}
   ```bash
    KEYCLOAK_REPLICAS=$(kubectl get sts --namespace keycloak keycloak -o custom-columns=:status.replicas --no-headers)
    kubectl scale sts --namespace keycloak keycloak --replicas=0
    kubectl scale sts --namespace keycloak keycloak --replicas=${KEYCLOAK_REPLICAS}
    kubectl wait --namespace keycloak --for=condition=ready pod -l app.kubernetes.io/instance=keycloak --timeout=600s
   ```
   {{< /clipboard >}}

### Update Verrazzano secrets in the new cluster

The following steps are applicable only if you are restoring Keycloak on a new cluster.

After you complete the MySQL restore operation, the password for the following secrets in the
`verrazzano-system` namespace must be updated in the new cluster:
- `verrazzano`
- `verrazzano-es-internal`
- `verrazzano-prom-internal`

1. On the original cluster, run the following command for the `verrazzano` secret:   
   {{< clipboard >}}
   ```bash
    $ kubectl get secret --namespace verrazzano-system verrazzano -o jsonpath={.data.password}; echo
   ```
   {{< /clipboard >}}

2. On the new cluster, replace the existing password value with the value displayed in step 1.
   {{< clipboard >}}
   ```bash
    kubectl patch secret verrazzano --namespace verrazzano-system -p '{"data": {"password": "<password displayed in step 1>"}}'
   ```
   {{< /clipboard >}}

3. Repeat steps 1 and 2 for the `verrazzano-es-internal` and `verrazzano-prom-internal` secrets.

4. Restart the `fluentd` pods in the new cluster to use the original cluster password to connect to OpenSearch.
   {{< clipboard >}}
   ```bash
    $ kubectl delete pod -l app=fluentd --namespace verrazzano-system
   ```
   {{< /clipboard >}}
