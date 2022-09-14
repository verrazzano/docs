---
title: Restore
description: "Restore component-specific persistent data and configurations"
linkTitle: Restore
weight: 3
draft: false
---


Before proceeding, ensure that the backup component prerequisites are met, as indicated [here]({{< relref "docs/setup/backup/prerequisites.md" >}}).
This document also assumes that a successful backup was previously made using either Velero or rancher-backup, as shown [here]({{< relref "docs/setup/backup/backup.md" >}}).  

Use the following component-specific instructions to restore application data.

{{< tabs tabTotal="3" >}}
{{< tab tabName="RancherRestore" >}}
<br>

### Rancher Restore

To initiate a Rancher restore, create the following example custom resource YAML file.
When a `Restore` custom resource is created, the operator accesses the backup `*.tar.gz` file specified and restores the application data from that file.


```yaml
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
```

The rancher-backup operator scales down the Rancher deployment during the restore operation and scales it back up after the restoration completes.

Resources are restored in this order:

- Custom Resource Definitions (CRDs)
- Cluster-scoped resources
- Namespace resources

<br/>


{{< /tab >}}
{{< tab tabName="OpenSearch Restore" >}}
<br>

#### OpenSearch Restore

For OpenSearch, Verrazzano provides a custom hook that you can use along with Velero, to perform a restore operation.
Due to the nature of transient data handled by OpenSearch, the hook invokes OpenSearch snapshot APIs to back up and restore data streams appropriately,
thereby ensuring there is no loss of data and avoids data corruption as well.

To initiate an OpenSearch restore, first delete the existing OpenSearch cluster running on the system and all related data.

- Scale down `Verrazzano Monitoring Operator`.

```shell
$ kubectl scale deploy -n verrazzano-system verrazzano-monitoring-operator --replicas=0
```

- Then, clean up the OpenSearch components.

```shell
# These are sample commands to demonstrate the OpenSearch restore process

$ kubectl delete sts -n verrazzano-system -l verrazzano-component=opensearch
$ kubectl delete deploy -n verrazzano-system -l verrazzano-component=opensearch
$ kubectl delete pvc -n verrazzano-system  -l verrazzano-component=opensearch

```

To perform an OpenSearch restore, you can invoke the following example Velero `Restore` [API](https://velero.io/docs/v1.8/api-types/restore/) object.

```yaml
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
$ velero restore logs verrazzano-opensearch-restore -n verrazzano-backup

# To examine the hook logs, exec into the pod as shown
$ kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/verrazzano-restore-hook-2357212430.log
```
</details>



<br/>
