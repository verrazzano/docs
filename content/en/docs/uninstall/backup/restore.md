---
title: Restore
description: "Restore component-specific persistent data and configurations"
linkTitle: Restore
weight: 3
draft: false
---


Before proceeding, ensure that the backup component prerequisites are met, as indicated in [Prerequisites]({{< relref "/docs/uninstall/backup/prerequisites.md" >}}).
This document also assumes that a successful backup was previously made using either Velero, rancher-backup, or MySQL Operator, as described in [Backup]({{< relref "/docs/uninstall/backup/backup.md" >}}).  

Use the following component-specific instructions to restore application data:
- [MySQL restore](#mysql-restore)
- [Rancher restore](#rancher-restore)
- [OpenSearch restore](#opensearch-restore)

## MySQL restore

To initiate a MySQL restore, from an existing backup, you need to recreate the MySQL cluster.

1. Back up the values in the MySQL Helm chart to a file, `mysql-values.yaml`.

   ```shell
    $ helm get values -n keycloak mysql > mysql-values.yaml
    ```

2. Get the backup folder prefix name that the MySQL backup created.

    ```shell
    $ kubectl get mysqlbackup -n keycloak <mysql-backup-name> -o jsonpath={.status.output}
    ```
    The following is an example:
    ```shell
    $ kubectl get mysqlbackup -n keycloak mysql-backup -o jsonpath={.status.output}
    mysql-backup-20221025-180836
    ```

3. Retrieve the MySQL Helm charts from Verrazzano platform operator.

    ```shell
    $ mkdir mysql-charts
    $ kubectl cp -n verrazzano-install \
        $(kubectl get pod -n verrazzano-install -l app=verrazzano-platform-operator \
        -o custom-columns=:metadata.name --no-headers):platform-operator/thirdparty/charts/mysql \
        -c verrazzano-platform-operator mysql-charts/
    ```

4. Clean up MySQL pods and PVC from the system.

    ```shell
    $ helm delete mysql -n keycloak
    $ kubectl delete pvc -n keycloak -l tier=mysql
    ```

5. Trigger a MySQL restore by running the Helm chart as follows.

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

6. After performing the restore command, wait for the MySQL cluster to be online . Ensure that the `STATUS` is `ONLINE` and the count under `ONLINE` matches the `INSTANCES`.

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

At this point, the MySQL cluster has been restored successfully from the backup, along with the PVCs that were cleaned up previously.

## Rancher restore

Restoring rancher is done by creating a custom resource that indicates to `rancher-backup` to start the restore process.

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


## OpenSearch restore

For OpenSearch, Verrazzano provides a custom hook that you can use along with Velero, to perform a restore operation.
Due to the nature of transient data handled by OpenSearch, the hook invokes OpenSearch snapshot APIs to back up and restore data streams appropriately,
thereby ensuring there is no loss of data and avoids data corruption as well.

To initiate an OpenSearch restore, first delete the existing OpenSearch cluster running on the system and all related data.

1. Scale down `Verrazzano Monitoring Operator`.

    ```shell
    $ kubectl scale deploy -n verrazzano-system verrazzano-monitoring-operator --replicas=0
    ```

2. Then, clean up the OpenSearch components.

    ```shell
    # These are sample commands to demonstrate the OpenSearch restore process

    $ kubectl delete sts -n verrazzano-system -l verrazzano-component=opensearch
    $ kubectl delete deploy -n verrazzano-system -l verrazzano-component=opensearch
    $ kubectl delete pvc -n verrazzano-system -l verrazzano-component=opensearch

    ```

3. To perform an OpenSearch restore, you can invoke the following example Velero `Restore` [API](https://velero.io/docs/v1.8/api-types/restore/) object.

   ```yaml
   $ kubectl apply -f - <<EOF
     apiVersion: velero.io/v1
     kind: Restore
     metadata:
       name: verrazzano-opensearch-restore
       namespace: verrazzano-backup
     spec:
       backupName: verrazzano-opensearch-backup
       includedNamespaces:
         - verrazzano-system
       labelSelector:
         matchLabels:
           verrazzano-component: opensearch
       restorePVs: false
       hooks:
         resources:
           - name: opensearch-test
             includedNamespaces:
               - verrazzano-system       
             labelSelector:
               matchLabels:            
                 statefulset.kubernetes.io/pod-name: vmi-system-es-master-0
             postHooks:
               - exec:
                   container: es-master
                   command:
                     - /usr/share/opensearch/bin/verrazzano-backup-hook
                     - -operation
                     - restore
                     - -velero-backup-name
                     - verrazzano-opensearch-backup
                   waitTimeout: 30m
                   execTimeout: 30m
                   onError: Fail
   EOF
   ```

4. Wait for all the OpenSearch pods to be in the `RUNNING` state.

   ```shell

    $ kubectl wait -n verrazzano-system --for=condition=ready pod -l verrazzano-component=opensearch --timeout=600s
      pod/vmi-system-es-data-0-6f49bdf6f5-fc6mz condition met
      pod/vmi-system-es-data-1-8f8785994-4pr7n condition met
      pod/vmi-system-es-data-2-d5f569d98-q8p2v condition met
      pod/vmi-system-es-ingest-6ddd86b9b6-fpl6j condition met
      pod/vmi-system-es-ingest-6ddd86b9b6-jtmrh condition met
      pod/vmi-system-es-master-0 condition met
      pod/vmi-system-es-master-1 condition met
      pod/vmi-system-es-master-2 condition met
    ```


The preceding example will restore an OpenSearch cluster from an existing backup.
- It will recreate a new OpenSearch cluster (with new indexes).
- The `postHook` will invoke the OpenSearch APIs that restores the snapshot data.
- The container on which the hook needs to be run is identified by the pod label selectors, followed by the container name.
  In this case, it's `statefulset.kubernetes.io/pod-name: vmi-system-es-master-0`.

**NOTE**: The hook needs to be a `postHook` because it must be applied after the Kubernetes objects are restored.

After the restore operation is processed, you can see the hook logs using the `velero restore logs` command. Additionally, the hook logs are stored under the `/tmp` folder in the pod.


<details>
  <summary>OpenSearch restore logs</summary></summary>

```shell
# To display the logs from the restore, run the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero

# Fetch the log file name as shown
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- ls -al /tmp | grep verrazzano-restore-hook | tail -n 1 | awk '{print $NF}'

# To examine the hook logs, exec into the pod as shown, and use the file name retrieved previously
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/<log-file-name>

```
</details>
