---
title: "Configure NFS Storage"
weight: 10
draft: false
aliases:
  - /docs/customize/nfs.md
---

Complete the following steps to configure NFS storage in an Oracle Cloud Native Environment.

1. Create an OLCNE cluster. See [OLCNE cluster](https://docs.oracle.com/en/operating-systems/olcne/1.1/start/intro.html).

   The cluster must have at least 3 worker nodes.

2. Create an NFS server. For an example that uses an NFS server on Oracle Linux, see [Create an NFS server on Oracle Linux](https://docs.oracle.com/en/learn/create_nfs_linux/).

   a. Install the NFS utility package on the server and client instances.
{{< clipboard >}}
<div class="highlight">

  ```
  $ sudo dnf install -y nfs-utils
  ```

</div>
{{< /clipboard >}}

   b. Create a directory for your shared files. Make sure that the server does not have root ownership.

   c. Define the shared directory in ```/etc/exports``` with the correct permissions. Make sure to disable root squashing.
{{< clipboard >}}
<div class="highlight">

   ```
   $ <path to directory> <ip-address/subnet-mask>(rw,sync,no_root_squash,no_subtree_check)
   ```

</div>
{{< /clipboard >}}

   d. Set the firewall to allow NFS traffic.
{{< clipboard >}}
<div class="highlight">

   ```
 $ sudo firewall-cmd --permanent --zone=public --add-service=nfs
 $ sudo firewall-cmd --reload
 $ sudo firewall-cmd --list-all
   ```

</div>
{{< /clipboard >}}

   e. Enable and start the NFS service.
{{< clipboard >}}
<div class="highlight">

   ```
   $ sudo systemctl enable --now nfs-server
   ```
</div>
{{< /clipboard >}}

3. Deploy an NFS provisioner to your cluster.

   a. Install an NFS client provisioner of your choice. For an example, see [Kubernetes NFS Subdir External Provisioner](https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner).  

   b. Add the required Helm repo.
{{< clipboard >}}
<div class="highlight">

   ```
   $ helm repo add nfs-subdir-external-provisioner https://kubernetes-sigs.github.io/nfs-subdir-external-provisioner/
   ```

</div>
{{< /clipboard >}}

   c. Install the provisioner. Set your storage class as a default and create a service account.
{{< clipboard >}}
<div class="highlight">

   ```
   $ helm install nfs-test \
      --set nfs.server=<server ip address> \
      --set nfs.path=<path> \
      --set storageClass.name=<name> \
      --set storageClass.defaultClass=true,rbac.create=true \
      --set storageClass.provisionerName=nfsclientprov/nfs \
      --set serviceAccount.create=true \
      --set serviceAccount.name=nfs-svc-acc-nfs nfs-subdir-external-provisioner/nfs-subdir-external-provisioner
   ```

</div>
{{< /clipboard >}}

   d. Only one storage class should be listed as the default. If required, edit the other storage classes and delete the following annotation:
{{< clipboard >}}
<div class="highlight">

   ```
   $ storageclass.kubernetes.io/is-default-class: "true"
   ```     

</div>
{{< /clipboard >}}
