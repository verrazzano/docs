---
title: "Multicluster Verrazzano setup"
linkTitle: Multicluster Setup
description: "How to setup a multicluster Verrazzano environment"
weight: 8
draft: false
---

This page covers the following topics.

- [Set up a multicluster Verrazzano environment](#set-up-a-multicluster-verrazzano-environment)
- [Run applications in multicluster Verrazzano](#run-applications-in-multicluster-verrazzano)
- [View clusters and applications in the admin cluster UI](#view-clusters-and-applications-in-the-admin-cluster-ui)

## Set up a multicluster Verrazzano environment

To set up a multicluster Verrazzano environment, you will need two or more Kubernetes clusters. One of these clusters
will be used as the **admin** cluster and the others will be used as **managed** clusters.

The instructions here assume that you are using an admin cluster and a single managed cluster. For each additional managed
cluster you are using, simply repeat the managed cluster instructions.

### Required Reading

Before setting up a multicluster Verrazzano environment, please read the 
[multicluster concepts](../../../concepts/verrazzanomulticluster "multicluster concepts") document.

### Install Verrazzano

Install Verrazzano on each Kubernetes cluster individually.

- On one cluster, install Verrazzano using the **dev** profile; this will be used as the *admin* cluster.
- On the other cluster, install Verrazzano using the **managed-cluster** profile; this will be used as a
  managed cluster. The managed-cluster profile contains only the components that are required on a managed cluster.
- Create the environment variables, KUBECONFIG_ADMIN and KUBECONFIG_MANAGED1, and point them to the kubeconfig file for 
  the admin and managed cluster, respectively. These environment variables will be used in subsequent steps when
  registering the managed cluster.  

The [installation guide](../../install/installation) has detailed instructions on how to install Verrazzano on a
Kubernetes cluster using a specific profile. 

### Register the managed cluster with the admin cluster

#### Pre-registration setup
We will need to first set up the following items before we can register the managed cluster.
- A config map containing the externally reachable address of the admin cluster. This will be provided to the managed
  cluster during registration, so that it can connect to the admin cluster.
- A secret containing the managed cluster's Prometheus endpoint. This will be used by the admin cluster to scrape
  metrics from the managed cluster, for both applications and Verrazzano components.

The steps for this setup are shown below.

1. Obtain the Kubernetes server address for the admin cluster, from its kubeconfig file.
    ```
    # If your kubeconfig has only a single context, or has the admin cluster's context set as the current-context
    $ ADMIN_K8S_SERVER_ADDRESS="$(kubectl config view --minify | grep server | cut -f2- -d: | tr -d " ")

    # If your kubeconfig has multiple contexts, list the kubeconfig contexts and find the name of context corresponding
    # to the admin cluster
    $ kubectl config get-contexts
    # Replace "admin-server-context-name" with the name of the context corresponding to your admin cluster.
    $ ADMIN_K8S_SERVER_ADDRESS="$(kubectl --context admin-server-context-name config view --minify | grep server | cut -f2- -d: | tr -d " ")
    ```

1. Create a ConfigMap that contains the Kubernetes server address of the admin cluster.
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

1. Obtain the credentials for scraping metrics from the managed cluster.  Use the following instructions to output the credentials to a file named `managed1.yaml` in the current folder.
   ```
   $ export KUBECONFIG=$KUBECONFIG_MANAGED1
   $ echo "prometheus:" > managed1.yaml
   $ echo "  host: $(KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl get ing vmi-system-prometheus -n verrazzano-system -o jsonpath='{.spec.tls[0].hosts[0]}')" >> managed1.yaml
   $ echo "  cacrt: |" >> managed1.yaml
   $ echo -e "$(KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl -n verrazzano-system get secret system-tls -o jsonpath='{.data.ca\.crt}' | base64 --decode)" | sed 's/^/    /' >> managed1.yaml
   ```

1. Create a secret on the admin cluster that contains the credentials for scraping metrics from the managed cluster.
   The file `managed1.yaml` that was created in the previous step provides input to this step.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl create secret generic prometheus-managed1 -n verrazzano-mc --from-file=managed1.yaml
   ```

#### Registration steps
1. Apply the VerrazzanoManagedCluster object on the admin cluster to begin the registration process for a managed cluster named `managed1`.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply -f <<EOF -
   apiVersion: clusters.verrazzano.io/v1alpha1
   kind: VerrazzanoManagedCluster
   metadata:
     name: managed1
     namespace: verrazzano-mc
   spec:
     description: "Test VerrazzanoManagedCluster object"
     prometheusSecret: prometheus-managed1
   EOF
   ```
1. Wait for the VerrazzanoManagedCluster resource to reach ready status. At that point, it will have generated a YAML
   file that is to be applied on the managed cluster to complete the registration process.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl wait --for=condition=Ready vmc managed1 -n verrazzano-mc
   ```
1. Export the YAML file created to register the managed cluster.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl get secret verrazzano-cluster-managed1-manifest -n verrazzano-mc -o jsonpath={.data.yaml} | base64 --decode > register.yaml
   ```

1. Apply the registration file on the managed cluster.
   ```
   $ KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl apply -f register.yaml
   ```

## Run applications in multicluster Verrazzano

The Verrazzano multicluster set up is now completed, and you can deploy an application by following the [Hello World Helidon multicluster example application](https://github.com/verrazzano/verrazzano/tree/master/examples/multicluster/hello-helidon).

## View clusters and applications in the admin cluster UI

The admin cluster serves as a central point from which to register and deploy applications to managed clusters.
In the Verrazzano UI on the admin cluster, you can view the list of managed clusters registered with this admin cluster,
as well as applications deployed to those managed clusters. 

### Managed clusters in the Verrazzano UI

Registered managed clusters can be viewed in the admin cluster's Verrazzano UI as shown in the screenshot below.

![](../../../images/multicluster/MCClustersScreenshot.png)

### Multicluster applications in the admin Verrazzano UI

Multicluster applications deployed to various managed clusters can be viewed in the admin cluster's Verrazzano UI as
shown in the screenshot below.

![](../../../images/multicluster/MCAppScreenshot.png)
