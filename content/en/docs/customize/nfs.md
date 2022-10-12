---
title: "Network File System"
description: "Configuring NFS Storage"
linkTitle: Network File System
weight: 4
draft: false
---

### Oracle Cloud Native Environment

* Create an [OLCNE cluster](https://docs.oracle.com/en/operating-systems/olcne/1.1/start/intro.html):

  - The cluster must have at least 3 worker nodes.

* Create an NFS server:

  - [Here](https://docs.oracle.com/en/learn/create_nfs_linux/) is an example using an NFS server on Oracle Linux. 
  - Install the NFS utilities package on the server and client instances:

    ``` 
    sudo dnf install -y nfs-utils

  - Create a directory to contain your shared files.

    - The server must not have root ownership

  - Define the share in /etc/exports with the correct permissions. Make sure to disable root squashing:

    ```
    <path to directory> 100.101.68.0/24(rw,sync,no_root_squash,no_subtree_check)

  - Set the firewall to allow NFS traffic:

     ```
     sudo firewall-cmd --permanent --zone=public --add-service=nfs
     sudo firewall-cmd --reload
     sudo firewall-cmd --list-all

  - Enable and start the NFS service.

     ```
     sudo systemctl enable --now nfs-server

* Deploy an NFS provisioner to your cluster.

  - Once you have an NFS server, install an NFS client provisioner of your choice. Here is an example using [Kubernetes NFS Subdir External Provisioner](https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner)  
  - First, add the required helm repo: 

    ```
    helm repo add nfs-subdir-external-provisioner https://kubernetes-sigs.github.io/nfs-subdir-external-provisioner/
  
  - Then, install the provisioner. Set your storage class as default and create a service account: 

      ```
      helm install nfs-test \
         --set nfs.server=<server ip address> \
         --set nfs.path=<path> \
         --set storageClass.name=<name> \
         --set storageClass.defaultClass=true,rbac.create=true \
         --set storageClass.provisionerName=nfsclientprov/nfs \
         --set serviceAccount.create=true \
         --set serviceAccount.name=nfs-svc-acc-nfs nfs-subdir-external-provisioner/nfs-subdir-external-provisioner
    
  - Only one storage class should be listed as default. If necessary, edit the other storage classes and delete the following annotation: 
  
     ```
    service.beta.kubernetes.io/oci-load-balancer-internal: "true"