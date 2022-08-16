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
{{< tab tabName="MySQL Restore" >}}
<br>

### MySQL Restore

For MySQL, Verrazzano provides a custom hook that you can use along with Velero, to perform a restore operation.

To initiate a complete MySQL restore, first delete the `keycloak` namespace.

```shell
$ kubectl delete namespace keycloak
```

To perform a MySQL restore, you can invoke the following example of a Velero `Restore` [API](https://velero.io/docs/v1.8/api-types/restore/) object.

```yaml
apiVersion: velero.io/v1
kind: Restore
metadata:
  name: verrazano-mysql-restore-example
  namespace: verrazzano-backup
spec:
  backupName: verrazzano-mysql-backup-example
  includedNamespaces:
    - keycloak
  restorePVs: true
  hooks:
    resources:
      - name: mysql-resource
        includedNamespaces:
          - keycloak        
        labelSelector:
          matchLabels:
            app: mysql
        postHooks:
          - exec:
              container: mysql
              command:
                - bash
                - /etc/mysql/conf.d/mysql-hook.sh
                - -o restore
                - -f mysql-backup-test.sql
              waitTimeout: 5m
              execTimeout: 5m
              onError: Fail

```

The preceding example restores the `keycloak` namespace and the `mysql` volumes.
- It will recreate the MySQL PVCs along with the MySQL pods.
- The `postHook` will restore the MySQL data and ensure that there are no inconsistencies.
- The container on which the hook needs to be executed is identified by the pod label selectors, followed by the container name.


**NOTE**: The hook needs to be a `postHook` because it must be applied after the Kubernetes objects are restored.

To understand the progress of the restore operation, you can monitor the Velero `Restore` object.

<details>
  <summary>MySQL restore progress</summary>

```shell
# The following command lets you monitor the restore progress
$ velero restore get -n verrazzano-backup                                                           
NAME                              BACKUP              STATUS       STARTED                         COMPLETED   ERRORS   WARNINGS   CREATED                         SELECTOR
verrazano-mysql-restore-example   mysql-backup-test   InProgress   2022-07-07 17:00:33 -0700 PDT   <nil>       0        0          2022-07-07 17:00:33 -0700 PDT   <none>
```

</details>

<details>
  <summary>MySQL Restore object details</summary>

```shell
# Command to get details about the Restore object

$ velero restore describe verrazano-mysql-restore-example -n verrazzano-backup

# Sample output

Name:         verrazano-mysql-restore-example
Namespace:    verrazzano-backup
Labels:       <none>
Annotations:  kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"velero.io/v1","kind":"Restore","metadata":{"annotations":{},"name":"mysql-backup-restore","namespace":"velero"},"spec":{"backupName":"nysql-backup-test","hooks":{"resources":[{"includedNamespaces":["keycloak"],"labelSelector":{"matchLabels":{"app":"mysql"}},"name":"verrazzano-sql-restore","postHooks":[{"exec":{"command":["bash","/etc/mysql/conf.d/mysql-hook.sh","-o restore","-f sunday.sql"],"container":"mysql","execTimeout":"5m","onError":"Fail","waitTimeout":"5m"}}]}]},"includedNamespaces":["keycloak"],"restorePVs":true}}


Phase:                       Completed
Total items to be restored:  40
Items restored:              40

Started:    2022-07-07 17:00:33 -0700 PDT
Completed:  2022-07-07 17:02:14 -0700 PDT

Backup:  nysql-backup-test

Namespaces:
  Included:  keycloak
  Excluded:  <none>

Resources:
  Included:        *
  Excluded:        nodes, events, events.events.k8s.io, backups.velero.io, restores.velero.io, resticrepositories.velero.io
  Cluster-scoped:  auto

Namespace mappings:  <none>

Label selector:  <none>

Restore PVs:  true

Restic Restores:
  Completed:
    keycloak/keycloak-0: istio-envoy, theme
    keycloak/mysql-5df654b5fd-8n4vv: data, istio-envoy

Preserve Service NodePorts:  auto
```

</details>

<details>
  <summary>Pod volume restore details</summary></summary>

```shell
# The following command lists all the pod volume restored, that were created by Velero
$ kubectl get podvolumerestores -n verrazzano-backup                        

```
</details>

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
