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
- Create the environment variables, `KUBECONFIG_ADMIN` and `KUBECONFIG_MANAGED1`, and point them to the `kubeconfig`
  files for the admin and managed cluster, respectively. These environment variables will be used in subsequent steps
  when registering the managed cluster.

For detailed instructions on how to install Verrazzano on a Kubernetes cluster using a specific profile, see the
[Installation Guide]({{< relref "/docs/setup/install/installation.md" >}}).

## Register the managed cluster with the admin cluster

The following sections show you how to register the managed cluster with the admin cluster.

<!-- omit in toc -->
### Preregistration setup

Before registering the managed cluster, first you'll need to set up the following items:
- A ConfigMap containing the externally reachable address of the admin cluster. This will be provided to the managed
  cluster during registration so that it can connect to the admin cluster.
- A Secret containing the managed cluster's CA certificate. Upon registration of the managed cluster, the host address of the Prometheus instance running on  the managed cluster is populated as `prometheusHost` in the `Status` field of the `VerrazzanoManagedCluster` resource created in the admin cluster. This CA certificate and the value of  `prometheusHost` is used by the admin cluster to scrape metrics from the managed cluster, for both applications and Verrazzano components.

Follow these preregistration setup steps:

1. Obtain the Kubernetes server address for the admin cluster from its `kubeconfig` file.
    ```
    # If your kubeconfig has only a single context, or has the admin cluster's context set as the current-context
    $ ADMIN_K8S_SERVER_ADDRESS="$(kubectl config view --minify | grep server | cut -f2- -d: | tr -d ' ')"

    # If your kubeconfig has multiple contexts, list the kubeconfig contexts and find the name of context corresponding
    # to the admin cluster
    $ kubectl config get-contexts
    # Replace "admin-server-context-name" with the name of the context corresponding to your admin cluster.
    $ ADMIN_K8S_SERVER_ADDRESS="$(kubectl --context admin-server-context-name config view --minify | grep server | cut -f2- -d: | tr -d ' ')"
    ```

1. Create a ConfigMap that contains the Kubernetes server address for the admin cluster.
    ```
    $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply -f <<EOF -
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: verrazzano-admin-cluster
      namespace: verrazzano-mc
    data:
      server: "${ADMIN_K8S_SERVER_ADDRESS}"
    EOF
    ```

1. Obtain the CA certificate used by the managed cluster.  Use the following instructions to write the CA certificate as part of a secret to a file named `managed1.yaml` in the current folder.
   ```
   $ export KUBECONFIG=$KUBECONFIG_MANAGED1
   $ CA_SECRET_FILE=managed1.yaml
   $ TLS_SECRET=$(kubectl -n verrazzano-system get secret system-tls -o json | jq -r '.data."ca.crt"')
   $ if [ ! -z "${TLS_SECRET%%*( )}" ] && [ "null" != "${TLS_SECRET}" ] ; then \
      CA_CERT=$(kubectl -n verrazzano-system get secret system-tls -o json | jq -r '.data."ca.crt"' | base64 \
      --decode); \
     fi
   $ if [ ! -z "${CA_CERT}" ] ; then \
      kubectl create secret generic "ca-secret-managed1" \
      -n verrazzano-mc --from-literal=cacrt="$CA_CERT" \
      --dry-run=client -o yaml > ${CA_SECRET_FILE}; \
     fi
   ```

1. Create a Secret on the admin cluster that contains the CA certificate for the managed cluster. This secret will be used for scraping metrics from the managed cluster.
   The file `managed1.yaml` that was created in the previous step provides input to this step.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply -f managed1.yaml
   ```

<!-- omit in toc -->
### Registration steps
1. To begin the registration process for a managed cluster named `managed1`, apply the VerrazzanoManagedCluster object on the admin cluster.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply -f <<EOF -
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
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl wait \
       --for=condition=Ready vmc managed1 \
       -n verrazzano-mc
   ```
1. Export the YAML file created to register the managed cluster.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl get secret verrazzano-cluster-managed1-manifest \
       -n verrazzano-mc \
       -o jsonpath={.data.yaml} | base64 \
       --decode > register.yaml
   ```

1. Apply the registration file on the managed cluster.
   ```
   $ KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl apply -f register.yaml
   ```

## Run applications in multicluster Verrazzano

The Verrazzano multicluster setup is now complete and you can deploy applications by following the [Multicluster Hello World Helidon]({{< relref "/docs/samples/multicluster/hello-helidon/_index.md" >}}) example application.

## Use the admin cluster UI

The admin cluster serves as a central point from which to register and deploy applications to managed clusters.

In the Verrazzano UI on the admin cluster, you can view the following:

- The managed clusters registered with this admin cluster.
- VerrazzanoProjects located on this admin cluster, or any of its registered managed clusters, or both.
- Applications located on this admin cluster, or any of its registered managed clusters, or both.
