---
title: "Rancher Backup"
description: "Backup rancher specific persistent data and configurations"
linkTitle: Rancher Backup
weight: 1
draft: false
---


Verrazzano offers `rancherBackup` as an operator to backup persistent data and configuration related to Rancher. More info about the operator can be found [here](https://rancher.com/docs/rancher/v2.5/en/backups/).

Ensure the operator is installed as indicated [here](/docs/setup/backup/installation/#backup-component-installation) and [prerequisites](/docs/setup/backup/prerequisites/#rancher-backup-operator-prerequisite)
are met before taking a backup. 

### Backing up Rancher

To initiate a Rancher backup create the following example custom resource YAML that will use S3 compatible object store as a backend. 

The app uses the `credentialSecretNamespace` value to determine where to look for the S3 backup secret. 

In the [prerequisites](/docs/setup/backup/prerequisites/#rancher-backup-operator-prerequisite) section, we had created the secret in `verrazzano-backup` namespace.

```yaml
apiVersion: resources.cattle.io/v1
kind: Backup
metadata:
  name: rancher-backup-test
spec:
  storageLocation:
    s3:
      credentialSecretName: rancher-backup-creds
      credentialSecretNamespace: verrazzano-backup
      bucketName: myvz-bucket
      folder: rancher-backup
      region: us-phoenix-1
      endpoint: mytenancy.compat.objectstorage.us-phoenix-1.oraclecloud.com
  resourceSetName: rancher-resource-set
```

Once a Backup custom resource is created, the `rancher-backup` operator calls the kube-apiserver to get the resources predefined with `rancher-backup` CRDs.

The operator then creates the backup file in the .tar.gz format and stores it in the location configured in the Backup resource in storageLocation field.

### Scheduled Backups

Similar to Velero, rancher-backup also allows [scheduled backups](https://rancher.com/docs/rancher/v2.5/en/backups/configuration/backup-config/).  
