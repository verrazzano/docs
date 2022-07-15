---
title: "Backup Component Install"
description: "Enabling Backup and Recovery component on Verrazzano platform"
linkTitle: Backup Component Install
weight: 1
draft: false
---

Verrazzano uses [velero](https://velero.io/docs/v1.8/) to perform backup and recovery at a component level or as a platform as a whole.

### Velero CLI Installation (optional)

Velero CLI helps in accessing velero objects in a more descriptive manner. The objects can also be managed using `kubectl`. 
The CLI can be installed on Oracle Linux as shown below

```shell
rpm -ivh https://yum.oracle.com/repo/OracleLinux/OL7/developer/olcne/x86_64/getPackage/velero-1.8.1-1.el7.x86_64.rpm
```

### Velero Component Installation 

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
```

Once installed you can check the pods running under `verrazzano-backup` namespace. 

```shell
kubectl get pod -n velero
NAME                      READY   STATUS    RESTARTS   AGE
restic-ndxfk              1/1     Running   0          21h
velero-5ff8766fd4-xbn4z   1/1     Running   0          21h
```