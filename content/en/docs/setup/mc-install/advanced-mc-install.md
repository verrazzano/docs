---
title: "Advanced Multicluster Installation"
description: "Set up a multicluster Verrazzano environment when Rancher is disabled"
weight: 12
draft: false
aliases:
  - /docs/setup/install/mc-install/advanced/advanced-mc-install
  - /docs/setup/install/mc-install/advanced/multicluster-no-rancher
---

Rancher is recommended for Verrazzano multicluster installations. However, if Rancher is not enabled on the _admin_ cluster, then registration requires you to perform a few additional steps.
The following instructions show you how to register a managed cluster when Rancher is not enabled in Verrazzano.


## Prerequisites

Before you begin, make sure you have completed the Prerequisites and Install Verrazzano, as described in [Install Multicluster Verrazzano]({{< relref "/docs/setup/mc-install/multicluster.md" >}}).

## Preregistration setup

Before registering the managed cluster, first you will need to set up the following items:
- A Secret containing the managed cluster's CA certificate. Note that the `cacrt` field in this secret can be empty only
  if the managed cluster uses a well-known CA.
  This CA certificate is used by the admin cluster to scrape metrics from the managed cluster, for both applications and Verrazzano components.
- A ConfigMap containing the externally reachable address of the admin cluster. This will be provided to the managed
  cluster during registration so that it can connect to the admin cluster.

Follow these preregistration setup steps.

1. If needed for the admin cluster, then obtain the managed cluster's CA certificate.
   The admin cluster scrapes metrics from the managed cluster's Prometheus endpoint. If the managed cluster
   Verrazzano installation uses self-signed certificates, then the admin
   cluster will need the managed cluster's CA certificate to make an `https` connection.
    - Depending on whether the Verrazzano installation on the managed cluster uses
      self-signed certificates or certificates signed by a well-known
      certificate authority, choose the appropriate instructions:

        - [Well-known CA](#well-known-ca)
        - [Self-signed certificates](#self-signed-certificates)

    - If you are unsure what type of certificates are used, use the following instructions.
        * To check the `ca.crt` field of the `verrazzano-tls` secret
          in the `verrazzano-system` namespace on the managed cluster:
{{< clipboard >}}
<div class="highlight">

```
# On the managed cluster
$ kubectl --kubeconfig $KUBECONFIG_MANAGED1 --context $KUBECONTEXT_MANAGED1 \
-n verrazzano-system get secret verrazzano-tls -o jsonpath='{.data.ca\.crt}'
```

</div>
{{< /clipboard >}}
          If this value is empty, then your managed cluster is using certificates signed by a well-known certificate
          authority. Otherwise, your managed cluster is using self-signed certificates.
<br>
          #### Well-known CA

          In this case, no additional configuration is necessary.

          #### Self-signed certificates

          If the managed cluster certificates are self-signed, create a file called `managed1.yaml` containing the CA
          certificate of the managed cluster as the value of the `cacrt` field. In the following commands, the managed cluster's
          CA certificate is saved in an environment variable called `MGD_CA_CERT`. Then use the `--dry-run` option of the
          `kubectl` command to generate the `managed1.yaml` file.
{{< clipboard >}}
<div class="highlight">

```
# On the managed cluster
$ export MGD_CA_CERT=$(kubectl --kubeconfig $KUBECONFIG_MANAGED1 --context $KUBECONTEXT_MANAGED1 \
   get secret verrazzano-tls \
   -n verrazzano-system \
   -o jsonpath="{.data.ca\.crt}" | base64 --decode)
$ kubectl --kubeconfig $KUBECONFIG_MANAGED1 --context $KUBECONTEXT_MANAGED1 \
create secret generic "ca-secret-managed1" \
-n verrazzano-mc \
--from-literal=cacrt="$MGD_CA_CERT" \
--dry-run=client \
-o yaml > managed1.yaml
```

</div>
{{< /clipboard >}}

          Create a Secret on the *admin* cluster that contains the CA certificate for the managed cluster. This secret will be used for scraping metrics from the managed cluster.
          The `managed1.yaml` file that was created in the previous step provides input to this step.
{{< clipboard >}}
<div class="highlight">

```
# On the admin cluster
$ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
   apply -f managed1.yaml

# After the command succeeds, you may delete the managed1.yaml file
$ rm managed1.yaml
```

</div>
{{< /clipboard >}}

1. Use the following instructions to obtain the Kubernetes API server address for the admin cluster.
This address must be accessible from the managed cluster.
    - [Most Kubernetes clusters](#most-kubernetes-clusters)
    - [kind clusters](#kind-clusters)

    #### Most Kubernetes clusters

    For most types of Kubernetes clusters, except for kind clusters, you can find the externally accessible API server
    address of the admin cluster from its kubeconfig file.
<br>
{{< clipboard >}}
<div class="highlight">

```
# View the information for the admin cluster in your kubeconfig file
$ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN config view --minify

# Sample output
apiVersion: v1
kind: Config
clusters:
- cluster:
  certificate-authority-data: DATA+OMITTED
  server: https://11.22.33.44:6443
  name: my-admin-cluster
contexts:
....
....
```
</div>
{{< /clipboard >}}
<br>
  In the output of this command, you will find the URL of the admin cluster API server in the `server` field. Set the
  value of the `ADMIN_K8S_SERVER_ADDRESS` variable to this URL.
{{< clipboard >}}
<div class="highlight">

  ```
  $ export ADMIN_K8S_SERVER_ADDRESS=<the server address from the config output>
  ```

</div>
{{< /clipboard >}}

    #### kind clusters

    kind clusters run within a Docker container. If your admin and managed clusters are kind clusters, then the API server
    address of the admin cluster in its kubeconfig file is typically a local address on the host machine, which will not be
    accessible from the managed cluster. Use the `kind` command to obtain the `internal` kubeconfig of the admin
    cluster, which will contain a server address accessible from other kind clusters on the same machine, and therefore in
    the same Docker network.
{{< clipboard >}}
<div class="highlight">

  ```
  $ kind get kubeconfig --internal --name <your-admin-cluster-name> | grep server
  ```

</div>
{{< /clipboard >}}
  In the output of this command, you can find the URL of the admin cluster API server in the `server` field. Set the
  value of the `ADMIN_K8S_SERVER_ADDRESS` variable to this URL.
{{< clipboard >}}
<div class="highlight">

  ```
  $ export ADMIN_K8S_SERVER_ADDRESS=<the server address from the config output>
  ```

</div>
{{< /clipboard >}}

1. On the admin cluster, create a ConfigMap that contains the externally accessible admin cluster Kubernetes server
address found in the previous step.
To be detected by Verrazzano, this ConfigMap must be named `verrazzano-admin-cluster`.
{{< clipboard >}}
<div class="highlight">

```
# On the admin cluster
$ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
apply -f <<EOF -
apiVersion: v1
kind: ConfigMap
metadata:
  name: verrazzano-admin-cluster
  namespace: verrazzano-mc
data:
  server: "${ADMIN_K8S_SERVER_ADDRESS}"
EOF
```

</div>
{{< /clipboard >}}

<!-- omit in toc -->
## Registration steps

Perform the first three registration steps on the *admin* cluster, and the last step, on the *managed* cluster.
The cluster against which to run the command is indicated in each code block.

#### On the admin cluster

1. To begin the registration process for a managed cluster named `managed1`, apply the VerrazzanoManagedCluster resource on the admin cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       apply -f <<EOF -
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

</div>
{{< /clipboard >}}
1. Wait for the VerrazzanoManagedCluster resource to reach the `Ready` status. At that point, it will have generated a YAML
   file that must be applied on the managed cluster to complete the registration process.
{{< clipboard >}}
<div class="highlight">

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       wait --for=condition=Ready \
       vmc managed1 -n verrazzano-mc
   ```
</div>
{{< /clipboard >}}

1. Export the YAML file created to register the managed cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       get secret verrazzano-cluster-managed1-manifest \
       -n verrazzano-mc \
       -o jsonpath={.data.yaml} | base64 --decode > register.yaml
   ```

</div>
{{< /clipboard >}}

### On the managed cluster

Apply the registration file exported in the previous step, on the managed cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   # On the managed cluster
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 --context $KUBECONTEXT_MANAGED1 \
       apply -f register.yaml

   # After the command succeeds, you may delete the register.yaml file
   $ rm register.yaml
   ```

</div>
{{< /clipboard >}}


After this step, the managed cluster will begin connecting to the admin cluster periodically. When the managed cluster
connects to the admin cluster, it will update the `Status` field of the `VerrazzanoManagedCluster` resource for this
managed cluster, with the following information:
- The timestamp of the most recent connection made from the managed cluster, in the `lastAgentConnectTime` status field.
- The host address of the Prometheus instance running on the managed cluster, in the `prometheusHost` status field. Then this is
  used by the admin cluster to scrape metrics from the managed cluster.
- The API address of the managed cluster, in the `apiUrl` status field. This is used by the admin cluster's authentication proxy to
  route incoming requests for managed cluster information, to the managed cluster's authentication proxy.

### Verify that managed cluster registration has completed

After these steps have been completed, return to [Verify that managed cluster registration has completed]({{< relref "/docs/setup/mc-install/verify-install.md#verify-that-managed-cluster-registration-has-completed" >}}).

## Deregister a managed cluster without Rancher

**NOTE**: The following procedure is for a Verrazzano multicluster environment in which Rancher is not enabled on the admin cluster.
If Rancher is enabled, see [Deregister a managed cluster]({{< relref "docs/setup/mc-install/deregister-install/_index.md" >}}).

If you want to deregister a managed cluster because you no longer want it to be part of a Verrazzano multicluster
environment, then complete the following steps.

### On the admin cluster
1. Export the YAML file created to register the managed cluster.
   {{< clipboard >}}
<div class="highlight">

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       get secret verrazzano-cluster-managed1-manifest \
       -n verrazzano-mc \
       -o jsonpath={.data.yaml} | base64 --decode > register.yaml
   ```

</div>
{{< /clipboard >}}

1. Delete the `VerrazzanoManagedCluster` resource on the admin cluster.
   {{< clipboard >}}
<div class="highlight">

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       delete vmc -n verrazzano-mc managed1
   ```

</div>
{{< /clipboard >}}


### On the managed cluster

Delete the resources in the registration file exported in the previous step, on the managed cluster.
   {{< clipboard >}}
<div class="highlight">

   ```
   # On the managed cluster
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 --context $KUBECONTEXT_MANAGED1 \
       delete -f register.yaml
   # After the command succeeds, you may delete the register.yaml file
   $ rm register.yaml
   ```

</div>
{{< /clipboard >}}
