---
title: "Backup Component Install"
description: "Enabling Backup and Recovery component on Verrazzano platform"
linkTitle: Backup Component Install
weight: 1
draft: false
---

Verrazzano uses [velero](https://velero.io/docs/v1.8/) and [rancher-backup](https://rancher.com/docs/rancher/v2.5/en/backups/) to perform backup and recovery at a component level or as a platform as a whole.

### Velero CLI Installation (optional)

Velero CLI helps in accessing velero objects in a more descriptive manner. The objects can also be managed using `kubectl`. 
The CLI can be installed on Oracle Linux as shown below

```shell
rpm -ivh https://yum.oracle.com/repo/OracleLinux/OL7/developer/olcne/x86_64/getPackage/velero-1.8.1-1.el7.x86_64.rpm
```

### Backup Component Installation 

Verrazzano offers the following operators to back up and restore persistent data:

- Velero
- Rancher Backup Operator

The following configuration is an example to enable the backup component with a `dev` installation profile:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  environmentName: default
  components:    
    velero:
      enabled: true
    rancherBackup:
      enabled: true  
```
**_NOTE:_** `rancherBackup` setting is honoured only in cases when `rancher` is also enabled.

Once installed you can check the pods running under `verrazzano-backup` namespace if the component is `velero`. 
For `rancherBackup` the pods will be created under `cattle-resources-system` namespace.   

```shell
# Sample of pods running after enabling velero component
kubectl get pod -n verrazzano-backup
NAME                      READY   STATUS    RESTARTS   AGE
restic-ndxfk              1/1     Running   0          21h
velero-5ff8766fd4-xbn4z   1/1     Running   0          21h
```

```shell
# Sample of pods running after enabling rancherBackup component
kubectl get pod -n cattle-resources-system
NAME                              READY   STATUS    RESTARTS   AGE
rancher-backup-5c4b985697-xw7md   1/1     Running   0          2d4h
```