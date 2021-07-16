---
title: "Install Multicluster Verrazzano"
description: "How to set up a multicluster Verrazzano environment"
weight: 5
draft: false
---

## Prerequisites

Before you begin, read this document, [Verrazzano in a multicluster environment]({{< relref "../../concepts/VerrazzanoMultiCluster.md" >}}).

## Overview

To set up a multicluster Verrazzano environment, you will need two or more Kubernetes clusters. One of these clusters
will the *admin* cluster; the others will be *managed* clusters.

The instructions here assume an admin cluster and a single managed cluster. For each additional managed
cluster, simply repeat the managed cluster instructions.

## Install Verrazzano

Install Verrazzano on each Kubernetes cluster.

- On one cluster, install Verrazzano using the `dev` or `prod` profile; this will be the *admin* cluster.
- On the other cluster, install Verrazzano using the `managed-cluster` profile; this will be a
  managed cluster. The `managed-cluster` profile contains only the components that are required for a managed cluster.

For detailed instructions on how to install and customize Verrazzano on a Kubernetes cluster using a specific profile,
see the [Installation Guide]({{< relref "/docs/setup/install/installation.md" >}}) and [Installation Profiles]({{< relref "/docs/setup/install/profiles.md" >}}).

## Register the managed cluster with the admin cluster

The following sections show you how to register the managed cluster with the admin cluster. As indicated, some of these
steps are performed on the admin cluster and some on the managed cluster.

<!-- omit in toc -->
### Preregistration setup

Before registering the managed cluster, first you'll need to set up the following items:
- A Secret containing the managed cluster's CA certificate. Note that the `cacrt` field in this secret can be empty if
  the managed cluster uses a well-known CA. It is required only if the managed cluster uses self-signed certificates.
  This CA certificate is used by the admin cluster to scrape metrics from the managed cluster, for both applications and Verrazzano components.
- A ConfigMap containing the externally reachable address of the admin cluster. This will be provided to the managed
  cluster during registration so that it can connect to the admin cluster.

Follow these preregistration setup steps:

1. If needed for the admin cluster, obtain the managed cluster's CA certificate.
   The admin cluster scrapes metrics from the managed cluster's Prometheus endpoint. If the managed cluster
   Verrazzano installation uses self-signed certificates, then the admin cluster will need the managed cluster's CA
   certificate in order to make an `https` connection.
   - Depending on whether the Verrazzano installation on the managed cluster uses
     self-signed certificates or certificates signed by a well-known certificate authority,
     choose the appropriate instructions.
   - If you are unsure what type of certificates are used, check for the `system-tls` secret in the `verrazzano-system` namespace
     on the managed cluster.
     ```shell
     # On the managed cluster
     $ kubectl -n verrazzano-system get secret system-tls
     ```
     If this secret is present, then your managed cluster is using self-signed certificates. If it is *not* present,
     then your managed cluster is using certificates signed by a well-known certificate authority.
     {{< tabs tabTotal="2" tabID="2" tabName1="Well-known CA" tabName2="Self-Signed" >}}
     {{< tab tabNum="1" >}}
<br>

In this case, create a file called `managed1.yaml` with an empty value for the `cacrt`
field as follows:

```shell
$ kubectl create secret generic "ca-secret-managed1" -n verrazzano-mc \
     --from-literal=cacrt="" --dry-run=client -o yaml > managed1.yaml;
```
     {{< /tab >}}
     {{< tab tabNum="2" >}}
<br>

If the managed cluster certificates are self-signed, create a file called `managed1.yaml` containing the CA
certificate of the managed cluster as the value of the `cacrt` field. In the following commands, the managed cluster's
CA certificate is saved in an environment variable called `MGD_CA_CERT`. Then use the `--dry-run` option of the
`kubectl` command to generate the `managed1.yaml` file.

```shell
# On the managed cluster
$ MGD_CA_CERT=$(kubectl -n verrazzano-system get secret system-tls \
     -o jsonpath="{.data.ca\.crt}" | base64 --decode)
$ kubectl create secret generic "ca-secret-managed1" -n verrazzano-mc \
     --from-literal=cacrt="$MGD_CA_CERT" --dry-run=client -o yaml > managed1.yaml;
```

     {{< /tab >}}
     {{< /tabs >}}


1. Create a Secret on the *admin* cluster that contains the CA certificate for the managed cluster. This secret will be used for scraping metrics from the managed cluster.
   The file `managed1.yaml` that was created in the previous step provides input to this step.
   ```shell
   # On the admin cluster
   $ kubectl apply -f managed1.yaml

   # Once the command succeeds, you may delete the managed1.yaml file
   $ rm managed1.yaml
   ```

1. Obtain the publicly accessible Kubernetes API server address for the admin cluster from its `kubeconfig` file, using
   the following instructions.
    ```shell
    # First list the contexts in the kubeconfig file - sample output is shown below
    $ kubectl config get-contexts -o=name
    my-admin-cluster
    my-managed-cluster
    ```

    ```shell
    # From the output, find the admin cluster's context name and use it in the next command
    # View the information for that context in your kubeconfig file 
    $ kubectl --context [your-admin-cluster-context-name] config view --minify
    apiVersion: v1
    kind: Config
    clusters:
    - cluster:
      certificate-authority-data: DATA+OMITTED
      server: https://127.0.0.1:46829
      name: kind-managed1
    contexts:
    ....
    ....
    ```

    ```shell
    # In the output of the above command, the address shown in the "server" field is the Kubernetes API server address.
    # Set the ADMIN_K8S_SERVER_ADDRESS environment variable to that value e.g. in the above sample output, the
    # value is https://127.0.0.1:46829
    $ export ADMIN_K8S_SERVER_ADDRESS=<the server address from the config output>
    ```

1. On the admin cluster, create a ConfigMap that contains the externally accessible admin cluster Kubernetes server
   address found in the previous step.
    ```shell
    # On the admin cluster
    $ kubectl apply -f <<EOF -
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: verrazzano-admin-cluster
      namespace: verrazzano-mc
    data:
      server: "${ADMIN_K8S_SERVER_ADDRESS}"
    EOF
    ```

<!-- omit in toc -->
### Registration steps
Perform the first three registration steps on the *admin* cluster, and the last step, on the *managed* cluster.
The cluster against which to run the command is indicated in each code block.
#### On the admin cluster
1. To begin the registration process for a managed cluster named `managed1`, apply the VerrazzanoManagedCluster object on the admin cluster.
   ```shell
   # On the admin cluster
   $ kubectl apply -f <<EOF -
   apiVersion: clusters.verrazzano.io/v1alpha1
   kind: VerrazzanoManagedCluster
   metadata:
     name: managed1
     namespace: verrazzano-mc
   spec:
     description: "Test VerrazzanoManagedCluster object"
     caSecret: ca-secret-managed1
   EOF
   ```
1. Wait for the VerrazzanoManagedCluster resource to reach the `Ready` status. At that point, it will have generated a YAML
   file that must be applied on the managed cluster to complete the registration process.

   ```shell
   # On the admin cluster
   $ kubectl wait --for=condition=Ready \
       vmc managed1 -n verrazzano-mc
   ```
1. Export the YAML file created to register the managed cluster.
   ```shell
   # On the admin cluster
   $ kubectl get secret verrazzano-cluster-managed1-manifest \
       -n verrazzano-mc \
       -o jsonpath={.data.yaml} | base64 --decode > register.yaml
   ```

#### On the managed cluster
Apply the registration file exported in the previous step, on the managed cluster.
   ```shell
   # On the managed cluster
   $ kubectl apply -f register.yaml

   # Once the command succeeds, you may delete the register.yaml file
   $ rm register.yaml
   ```
   After this step, the managed cluster will begin connecting to the admin cluster periodically. When the managed cluster
   connects to the admin cluster, it will update the `Status` field of the `VerrazzanoManagedCluster` resource for this
   managed cluster, with the following information:
   - The timestamp of the most recent connection made from the managed cluster, in the `lastAgentConnectTime` status field. 
   - The host address of the Prometheus instance running on the managed cluster, in the `prometheusHost` status field. This is
     then used by the admin cluster to scrape metrics from the managed cluster. 
   - The API address of the managed cluster, in the `apiUrl` status field. This is used by the admin cluster's API proxy to
     route incoming requests for managed cluster information, to the managed cluster's API proxy. 

### Verifying that managed cluster registration completed
You can perform all the verification steps on the admin cluster.

1. Verify that the managed cluster can connect to the admin cluster. View the status of the `VerrazzanoManagedCluster`
   resource on the admin cluster, and check whether the `lastAgentConnectTime`, `prometheusUrl` and `apiUrl` fields are
   populated. This may take up to 2 minutes after completing the registration steps.
   ```shell
   # On the admin cluster
   $ kubectl get vmc managed1 -o yaml
   
   # Sample output showing the status field
   spec:
     ....
     ....
   status:
     apiUrl: https://verrazzano.default.172.18.0.211.nip.io
     conditions:
     - lastTransitionTime: "2021-07-07T15:49:43Z"
       message: Ready
       status: "True"
       type: Ready
     lastAgentConnectTime: "2021-07-16T14:47:25Z"
     prometheusHost: prometheus.vmi.system.default.172.18.0.211.nip.io
   ```

2. Verify that the managed cluster is successfully registered with Rancher.
   When you perform the registration steps, Verrazzano also registers the managed cluster with Rancher. 
   View the Rancher UI on the admin cluster. Your cluster should be listed in Rancher's list of clusters, and should be
   in `Active` state if the registration with Rancher was successful. You can find the Rancher UI URL for your cluster
   by following the instructions for [Accessing Verrazzano]({{< relref "/docs/operations/_index.md" >}}).

## Run applications in multicluster Verrazzano

The Verrazzano multicluster setup is now complete and you can deploy applications by following the [Multicluster Hello World Helidon]({{< relref "/docs/samples/multicluster/hello-helidon/_index.md" >}}) example application.

## Use the admin cluster UI

The admin cluster serves as a central point from which to register and deploy applications to managed clusters.

In the Verrazzano UI on the admin cluster, you can view the following:

- The managed clusters registered with this admin cluster.
- VerrazzanoProjects located on this admin cluster, or any of its registered managed clusters, or both.
- Applications located on this admin cluster, or any of its registered managed clusters, or both.
