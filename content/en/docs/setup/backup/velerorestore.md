---
title: "Velero Restore"
description: "Restore data and configurations to Verrazzano platform"
linkTitle: Velero Restore
weight: 1
draft: false
---

Verrazzano includes specialized `hooks` to ensure a consistent restore experience with Velero.  More context on hooks can be found [here](https://velero.io/docs/v1.8/backup-hooks/).

Currently, the following components have in built hooks:
- MySQL
- OpenSearch

For all other components refer to `Velero` documentation for [restoring](https://velero.io/docs/v1.8/restore-reference/) data.


### MySQL Restore

For MySQL Verrazzano offers a custom hook that can be used along with Velero to perform a restore successfully.

Delete the `keycloak` namespace to initiate a complete MySQL restore.

```shell
kubectl delete namespace keycloak
```

Below example of Velero `Restore` [api](https://velero.io/docs/v1.8/api-types/restore/) object that can be invoked to perform a MySQL restore.

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

**_NOTE:_** The hook needs to be a `postHook` since we want to apply it after the Kubernetes objects are restored.

We can monitor the Velero restore object to understand the progress of our restore.

<details>
  <summary>MySQL Restore Progress</summary>

```shell
# The following command allows us to monitor the restore progress.
velero restore get -n verrazzano-backup                                                           
NAME                              BACKUP              STATUS       STARTED                         COMPLETED   ERRORS   WARNINGS   CREATED                         SELECTOR
verrazano-mysql-restore-example   mysql-backup-test   InProgress   2022-07-07 17:00:33 -0700 PDT   <nil>       0        0          2022-07-07 17:00:33 -0700 PDT   <none>
```

</details>

<details>
  <summary>MySQL Restore Object details</summary>

```shell
# Command to get details about the restore object.

velero restore describe verrazano-mysql-restore-example -n verrazzano-backup

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
  <summary>Pod Volume restore details</summary></summary>

```shell
# The following command lists all the pod volume restores, that were created by velero.. 
kubectl get podvolumerestores -n verrazzano-backup                        

```
</details>


#### OpenSearch Restore

For OpenSearch Verrazzano offers a custom hook that can be used along with Velero to perform a backup successfully.
Due to the nature of transient data handled by OpenSearch, the hook invokes OpenSearch snapshot apis to back up and restore data streams appropriately,
thereby ensuring there is no loss of data and avoids data corruption as well.

Delete existing OpenSearch cluster running on the system and all related data. 

- Scale down `Verrazzano Monitoring Operator`

```shell
kubectl scale deploy -n verrazzano-system verrazzano-monitoring-operator --replicas=0
```

- Cleanup OpenSearch components 

```shell
# These are sample commands to demonstrate the opensearh restore process.

kubectl delete sts -n verrazzano-system vmi-system-es-master
kubectl delete deploy -n verrazzano-system vmi-system-es-data-0
kubectl delete deploy -n verrazzano-system vmi-system-es-data-1
kubectl delete deploy -n verrazzano-system vmi-system-es-data-2
kubectl delete deploy -n verrazzano-system vmi-system-es-ingest
kubectl delete pvc -n verrazzano-system vmi-system-es-data
kubectl delete pvc -n verrazzano-system vmi-system-es-data-1
kubectl delete pvc -n verrazzano-system vmi-system-es-data-2
```

Below example is Velero restore [api](https://velero.io/docs/v1.8/api-types/restore/) object that can be invoked to take an OpenSearch restore.

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

In case of OpenSearch, during restore we perform the following actions:

- Recreate a new OpenSearch cluster.  
- Use a `postHook` to invoke the OpenSearch APIs that restores the snapshot data. That way we can get back the indices we had backed up prior to cleaning up. 


Once the restore is executed, the hook logs can be seen in the `velero restore logs` command. Additionally, the hook logs are also stored under `/tmp` folder in the pod itself.


<details>
  <summary>OpenSearch restore logs</summary></summary>

```shell

# To display the logs from the restore execute the following command
velero restore logs verrazzano-opensearch-restore -n verrazzano-backup

# To examine the hook logs exec into the pod as shown below
kubectl exec -it vmi-system-es-master-0 -n verrazzano-system -- cat /tmp/verrazzano-restore-hook-2357212430.log
```
</details>







