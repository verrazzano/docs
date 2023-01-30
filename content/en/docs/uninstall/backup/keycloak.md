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
- Object store region name.
- MySQL Operator uses OCI credentials to back up and restore MySQL data. Prior to starting a MySQL backup or restore operation, the MySQL Operator requires that a Kubernetes secret exists, consisting of the OCI credentials.

The following example creates a secret `mysql-backup-secret` in the namespace `keycloak`.

**NOTE:**  This secret must exist in the namespace `keycloak`.
{{< clipboard >}}

````shell
$ kubectl create secret generic -n keycloak  <secret-name> \
        --from-literal=user=<oci user id> \
        --from-literal=fingerprint=<oci user fingerprint> \
        --from-literal=tenancy=<oci tenancy id>> \
        --from-literal=region=<region where bucket is created> \
        --from-literal=passphrase="" \
        --from-file=privatekey=<full path to private key pem file>
````


The following is an example of creating a Kubernetes secret consisting of OCI credentials.

````shell
$ kubectl create secret generic -n keycloak  mysql-backup-secret \
        --from-literal=user=ocid1.user.oc1..aaaaaaaa \
        --from-literal=fingerprint=aa:bb:cc:dd:ee:ff \
        --from-literal=tenancy=ocid1.tenancy.oc1..bbbbbbbbb \
        --from-literal=region=us-phoenix-1 \
        --from-literal=passphrase="" \
        --from-file=privatekey=/tmp/key.pem
````

## MySQL Operator backup

To initiate a MySQL backup, create the following example custom resource YAML file that uses an OCI object store as a back end.
The operator uses the secret referenced in the `credentials` to authenticate with the OCI object store.

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
          ociObjectStorage:
            prefix: <prefix name. This folder will be auto created>
            bucketName: <object store bucket. This must be exist as noted in pre-requisites section>
            credentials: <Kubernetes secret name created in the prerequisite section>
EOF
```

**NOTE:**
- The `credentials` in `mysql-backup-secret` are those you created previously in the `keycloak` namespace.
- The `clustername` has to be `mysql`.
- The `namespace` has to be `keycloak`.

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
          ociObjectStorage:
            prefix: mysql-test
            bucketName: mysql-bucket
            credentials: mysql-backup-secret
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

3. Typically, the MySQL Helm charts are present inside the Verrazzano platform operator. Retrieve the charts to a local directory.

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
            --set tls.useSelfSigned=true \
            --set initDB.dump.name=<dump-name> \
            --set initDB.dumpOptions.loadUsers=true \
            --set initDB.dump.ociObjectStorage.prefix=<prefixName/backup folder name> \
            --set initDB.dump.ociObjectStorage.bucketName=<OCI bucket name> \
            --set initDB.dump.ociObjectStorage.credentials=<Credential Name> \
            --values <mysql values file>
   ```

   The following is an example:

    ```shell
    $ helm install mysql mysql-charts \
            --namespace keycloak \
            --set tls.useSelfSigned=true \
            --set initDB.dump.name="alpha" \
            --set initDB.dumpOptions.loadUsers=true \
            --set initDB.dump.ociObjectStorage.prefix="mysql-test/mysql-backup-20221025-180836" \
            --set initDB.dump.ociObjectStorage.bucketName="mysql-bucket" \
            --set initDB.dump.ociObjectStorage.credentials="mysql-backup-secret" \
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
{{< /clipboard >}}