---
title: Restore
description: "Restore component-specific persistent data and configurations"
linkTitle: Restore
weight: 3
draft: false
---


Before proceeding, ensure that the backup component prerequisites are met, as indicated [here]({{< relref "/docs/uninstall/backup/prerequisites.md" >}}).
This document also assumes that a successful backup was previously made using either Velero, rancher-backup, or MySQL Operator, as shown [here]({{< relref "/docs/uninstall/backup/backup.md" >}}).  

Use the following component-specific instructions to restore application data:
- [MySQL restore](#mysql-restore)
- [Rancher restore](#rancher-restore)
- [OpenSearch restore](#opensearch-restore)

## MySQL restore

To initiate a MySQL restore, from an existing backup, you need to recreate the MySQL cluster.

1. Back up the values in the MySQL Helm chart to a file, `mysql-values.yaml`.
    ```bash
    $ helm  get values -n keycloak mysql > mysql-values.yaml
    ```

2. Get the backup folder prefix name that the MySQL backup created.

    ```bash
    $ kubectl get mbk -n keycloak <mysql-backup-name> -o jsonpath={.status.output}
    ```

    The following is an example:
    ```bash
    $  kubectl get mbk -n keycloak mysql-backup -o jsonpath={.status.output}
    mysql-backup-20221025-180836
    ```

3. Clean up MySQL pods and PVC from the system.

    ```bash
    $ helm delete mysql -n keycloak
    $ kubectl delete pvc -n keycloak -l tier=mysql
    ```

4. Clone the MySQL Helm charts used by Verrazzano.

    ```bash
    $ git clone --filter=blob:none --no-checkout --depth 1 --sparse https://github.com/verrazzano/verrazzano
    $ cd verrazzano
    $ git sparse-checkout set platform-operator/thirdparty/charts/mysql
    $ git checkout
    ```


5. Trigger a MySQL restore by executing the Helm chart as follows.

    ```bash
    $ helm install mysql platform-operator/thirdparty/charts/mysql \
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

    ```bash
    $ helm install mysql platform-operator/thirdparty/charts/mysql \
            --namespace keycloak \
            --set tls.useSelfSigned=true \
            --set initDB.dump.name="alpha" \
            --set initDB.dumpOptions.loadUsers=true \
            --set initDB.dump.ociObjectStorage.prefix="mysql-test/mysql-backup-20221025-180836" \
            --set initDB.dump.ociObjectStorage.bucketName="mysql-bucket" \
            --set initDB.dump.ociObjectStorage.credentials="mysql-backup-secret" \
            --values mysql-values.yaml
    ```

Now, the MySQL cluster will be recreated and restored from the backup, along with the PVCs that were cleaned up previously.

## Rancher restore

To initiate a Rancher restore, create the following example custom resource YAML file.
When a `Restore` custom resource is created, the operator accesses the backup `*.tar.gz` file specified and restores the application data from that file.


```yaml
$ kubectl apply -f - <<EOF
  apiVersion: resources.cattle.io/v1
  kind: Restore
  metadata:
    name: s3-restore
  spec:
    backupFilename: rancher-backup-test-1111111-2222-3333-2022-07-26T02-44-21Z.tar.gz
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
    $ kubectl delete pvc -n verrazzano-system  -l verrazzano-component=opensearch

    ```

To perform an OpenSearch restore, you can invoke the following example Velero `Restore` [API](https://velero.io/docs/v1.8/api-types/restore/) object.

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


The preceding example will restore an OpenSearch cluster from an existing backup.
- It will recreate a new OpenSearch cluster (with new indexes).
- The `postHook` will invoke the OpenSearch APIs that restores the snapshot data.
- The container on which the hook needs to be executed is identified by the pod label selectors, followed by the container name.
  In this case, it's `statefulset.kubernetes.io/pod-name: vmi-system-es-master-0`.

**NOTE**: The hook needs to be a `postHook` because it must be applied after the Kubernetes objects are restored.

After the restore operation is executed, you can see the hook logs using the `velero restore logs` command. Additionally, the hook logs are stored under the `/tmp` folder in the pod.


<details>
  <summary>OpenSearch restore logs</summary></summary>

```shell
# To display the logs from the restore, execute the following command
$ kubectl logs -n verrazzano-backup -l app.kubernetes.io/name=velero

# Fetch the log file name as shown
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- ls -al /tmp | grep verrazzano-restore-hook | tail -n 1 | awk '{print $NF}'

# To examine the hook logs, exec into the pod as shown, and use the file name retrieved previously
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/<log-file-name>

```
</details>
