---
title: "Install Multicluster Verrazzano Without Rancher"
description: "How to set up a multicluster Verrazzano environment without Rancher installed"
weight: 3
draft: false
---

## Register the managed cluster with the admin cluster

The following sections show how to register a managed cluster if Rancher has not been installed with Verrazzano.
Rancher is recommended for Verrazzano multicluster installations.
If Rancher is not installed, then registration will require more steps.

## Prerequisites

Make sure you have completed the Prerequisites, Install Verrazzano, and Preregistration steps outlined in [Install Multicluster Verrazzano]({{< relref "/docs/setup/install/multicluster.md" >}}).

## Additional preregistration setup

Before registering the managed cluster, first you'll need to set up the following items.
- A Secret containing the managed cluster's CA certificate. Note that the `cacrt` field in this secret can be empty only
  if the managed cluster uses a well-known CA.
  This CA certificate is used by the admin cluster to scrape metrics from the managed cluster, for both applications and Verrazzano components.
- A ConfigMap containing the externally reachable address of the admin cluster. This will be provided to the managed
  cluster during registration so that it can connect to the admin cluster.

Follow these preregistration setup steps.

1. If needed for the admin cluster, obtain the managed cluster's CA certificate.
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
          ```
          # On the managed cluster
          $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 --context $KUBECONTEXT_MANAGED1 \
               -n verrazzano-system get secret verrazzano-tls -o jsonpath='{.data.ca\.crt}'
          ```
          If this value is empty, then your managed cluster is using certificates signed by a well-known certificate
          authority. Otherwise, your managed cluster is using self-signed certificates.

          #### Well-known CA

          In this case, no additional configuration is necessary.

          #### Self-signed certificates

          If the managed cluster certificates are self-signed, create a file called `managed1.yaml` containing the CA
          certificate of the managed cluster as the value of the `cacrt` field. In the following commands, the managed cluster's
          CA certificate is saved in an environment variable called `MGD_CA_CERT`. Then use the `--dry-run` option of the
          `kubectl` command to generate the `managed1.yaml` file.

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
          Create a Secret on the *admin* cluster that contains the CA certificate for the managed cluster. This secret will be used for scraping metrics from the managed cluster.
          The `managed1.yaml` file that was created in the previous step provides input to this step.
          ```
          # On the admin cluster
          $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
               apply -f managed1.yaml
   
          # After the command succeeds, you may delete the managed1.yaml file
          $ rm managed1.yaml
          ```

<!-- omit in toc -->
## Registration steps

Perform the first three registration steps on the *admin* cluster, and the last step, on the *managed* cluster.
The cluster against which to run the command is indicated in each code block.

#### On the admin cluster

1. To begin the registration process for a managed cluster named `managed1`, apply the VerrazzanoManagedCluster object on the admin cluster.
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
1. Wait for the VerrazzanoManagedCluster resource to reach the `Ready` status. At that point, it will have generated a YAML
   file that must be applied on the managed cluster to complete the registration process.

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       wait --for=condition=Ready \
       vmc managed1 -n verrazzano-mc
   ```
1. Export the YAML file created to register the managed cluster.
   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       get secret verrazzano-cluster-managed1-manifest \
       -n verrazzano-mc \
       -o jsonpath={.data.yaml} | base64 --decode > register.yaml
   ```

### On the managed cluster

Apply the registration file exported in the previous step, on the managed cluster.
   ```
   # On the managed cluster
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 --context $KUBECONTEXT_MANAGED1 \
       apply -f register.yaml

   # After the command succeeds, you may delete the register.yaml file
   $ rm register.yaml
   ```
After this step, the managed cluster will begin connecting to the admin cluster periodically. When the managed cluster
connects to the admin cluster, it will update the `Status` field of the `VerrazzanoManagedCluster` resource for this
managed cluster, with the following information:
- The timestamp of the most recent connection made from the managed cluster, in the `lastAgentConnectTime` status field.
- The host address of the Prometheus instance running on the managed cluster, in the `prometheusHost` status field. This is
  then used by the admin cluster to scrape metrics from the managed cluster.
- The API address of the managed cluster, in the `apiUrl` status field. This is used by the admin cluster's authentication proxy to
  route incoming requests for managed cluster information, to the managed cluster's authentication proxy.

### Verify that managed cluster registration has completed

Once these steps have been completed, you can return to [verify registration for multicluster installation]({{< relref "/docs/setup/install/multicluster.md#verify-that-managed-cluster-registration-has-completed" >}})
