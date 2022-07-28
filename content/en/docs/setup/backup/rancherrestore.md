---
title: "Rancher Restore"
description: "Restore rancher specific persistent data and configurations"
linkTitle: Rancher Restore
weight: 1
draft: false
---


Verrazzano offers `rancher-backup` as an operator to back up and restore persistent data and configuration related to Rancher. More info about the operator can be found [here](https://rancher.com/docs/rancher/v2.5/en/backups/).

Ensure the operator is installed as indicated [here](/docs/setup/backup/installation/#backup-component-installation) and [prerequisites](/docs/setup/backup/prerequisites/#rancher-backup-operator-prerequisite)
are met before taking a backup. 

### Restoring Rancher

To initiate a Rancher restore create the following example custom resource yaml.

When a Restore custom resource is created, the operator accesses the backup .tar.gz file specified by the Restore, and restores the application from that file.


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

The rancher-operator scales down the rancher deployment during restore, and scales it back up once the restore completes. 

The resources are restored in this order:

- Custom Resource Definitions (CRDs)
- Cluster-scoped resources
- Namespaced resources