---
title: "Keycloak Backup and Restore"
description: "Backing up and restoring keycloak data."
linkTitle: Keycloak Backup and Restore
weight: 2
draft: false
---

Verrazzano stores user login information in Keycloak. Keycloak, in turn uses MySQL as a backend to store all persistent data. 
Hence, in this document we will be covering how to back up and restore data stored in MySQL.

- [MySQL Operator prerequisites](#mysql-operator-prerequisites)
- [MySQL Operator Backup](#mysql-operator-backup)
- [MySQL Operator Restore](#mysql-operator-restore)

## MySQL Operator prerequisites

MySQL is deployed using the `MySQL operator`. The `MySQL operator`, apart from managing lifecycle of MySQL instances, also provides the capability to back up and restore data to and from OCI object store.
The following details should be kept handy before proceeding with MySQL back up or restore.

- Object store bucket name.
- Object store region name.
- MySQL Operator uses OCI credentials to back up and restore MySQL data. 

Prior to starting a MySQL backup or restore, the MySQL Operator requires that a Kubernetes secret exists, consisting of the OCI credentials.

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

## MySQL Operator Backup

To initiate a MySQL backup, create the following example custom resource YAML file that uses the OCI object store as a backend.
The operator would use the `credentials` to authenticate with the OCI object store.

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
- The `credentials` used here is `mysql-backup-secret`, is the same secret you created earlier in the `keycloak` namespace.
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

You can also implement schedules for running MYSQL backups. More details can be found here [MySQL Operator](https://dev.mysql.com/doc/mysql-operator/en/mysql-operator-backups.html) under `Backup schedule`s.

## MySQL Operator Restore

The following section assumes that you have read the [MySQL Operator prerequisites](#mysql-operator-prerequisites). Additionally, there should be at least one healthy back up before starting a restore. 

To initiate a MySQL restore, from an existing backup, you need to recreate the MySQL cluster. Following are sequence of steps for successful restoration of MySQL.

1. Back up the values in the MySQL Helm chart to a file, `mysql-values.yaml`.

   ```shell
    $ helm get values -n keycloak mysql > mysql-values.yaml
    ```

2. The MySQL backup creates a backup folder in the object store. You need to get the backup folder prefix name that the MySQL backup created.

    ```shell
    $ kubectl get mysqlbackup -n keycloak <mysql-backup-name> -o jsonpath={.status.output}
    ```
   The following is an example:
    ```shell
    $ kubectl get mysqlbackup -n keycloak mysql-backup -o jsonpath={.status.output}
    mysql-backup-20221025-180836
    ```

3. The MySQL Helm charts are normally present inside the Verrazzano platform operator. We need to retrieve the charts to a local directory.

    ```shell
    $ mkdir mysql-charts
    $ kubectl cp -n verrazzano-install \
        $(kubectl get pod -n verrazzano-install -l app=verrazzano-platform-operator \
        -o custom-columns=:metadata.name --no-headers):platform-operator/thirdparty/charts/mysql \
        -c verrazzano-platform-operator mysql-charts/
    ```

4. Delete MySQL pods and PVC from the system.

    ```shell
    $ helm delete mysql -n keycloak
    $ kubectl delete pvc -n keycloak -l tier=mysql
    ```

5. Now that you have removed MySQL from the system, trigger a MySQL restore by installing the Helm chart as follows.

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

The removal and recreation of the MySQL cluster may cause the Keycloak pods to go into crashloop state since MySQL goes offline during the restore operation.
Keycloak is set up to self-heal and will go into `Running` state once all backends are available. You may also choose to force Keycloak bring-up, by using the commands below

```shell
KEYCLOAK_REPLICAS=$(kubectl get sts -n keycloak keycloak -o custom-columns=:status.replicas --no-headers)
kubectl scale sts -n keycloak keycloak --replicas=0
kubectl scale sts -n keycloak keycloak --replicas=${KEYCLOAK_REPLICAS}
kubectl wait -n keycloak --for=condition=ready pod -l app.kubernetes.io/instance=keycloak -timeout=600s
```
