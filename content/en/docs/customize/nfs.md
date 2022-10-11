---
title: "Network File System"
description: "Installing Verrazzano with NFS"
linkTitle: Network File System
weight: 4
draft: false
---

### Oracle Cloud Native Environment

* Create an OLCNE cluster:

  - The cluster should have at least 3 worker nodes
  - set proxy and no proxy
  
* Create an NFS server:

  - [Example Documentation](/docs/reference/API/Verrazzano/v1beta1.md#ingress-component")
  - Disable root squashing 
  - The server must not have root ownership

* Set up NFS provisioner:

  - [Provisioner Option](https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner)
  - Create a storage class and set it as the default
  - Create a service account
  - Example:
    ```
    helm install nfs-test \
    --set nfs.server=<server ip address> \
    --set nfs.path=<path> \
    --set storageClass.name=<name> \
    --set storageClass.defaultClass=true,rbac.create=true \
    --set storageClass.provisionerName=nfsclientprov/nfs \
    --set serviceAccount.create=true \
    --set serviceAccount.name=nfs-svc-acc-nfs nfs-subdir-external-provisioner/nfs-subdir-external-provisioner
### Kind

### OKE

### Troubleshooting 

- Check that the proxy settings are correct 
  - if you change proxy and re apply, the change doesn’t take. must add it manually. when i added another worker node, the proxy was set correctly and i didn’t have to do it manually
    check /etc/exports on your nfs server





