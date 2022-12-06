---
title: "Install Multicluster Verrazzano"
description: "How to set up a multicluster Verrazzano environment"
weight: 3
draft: false
---

## Prerequisites

Before you begin, read this document, [Verrazzano in a multicluster environment]({{< relref "/docs/concepts/VerrazzanoMultiCluster.md" >}}).

## Overview

To set up a multicluster Verrazzano environment, you will need two or more Kubernetes clusters. One of these clusters
will the *admin* cluster; the others will be *managed* clusters.

The instructions assume an admin cluster and a single managed cluster. For each additional managed
cluster, simply repeat the managed cluster instructions.

## Install Verrazzano

Install Verrazzano on each Kubernetes cluster.

1. On one cluster, install Verrazzano using the `dev` or `prod` profile; this will be the *admin* cluster.
1. On the other cluster, install Verrazzano using the `managed-cluster` profile; this will be a
  managed cluster. The `managed-cluster` profile contains only the components that are required for a managed cluster.
1. Create the environment variables, `KUBECONFIG_ADMIN`, `KUBECONTEXT_ADMIN`, `KUBECONFIG_MANAGED1`, and
  `KUBECONTEXT_MANAGED1`, and point them to the kubeconfig files and contexts for the admin and managed cluster,
  respectively. You will use these environment variables in subsequent steps when registering the managed cluster. The
  following shows an example of how to set these environment variables.
     ```
     $ export KUBECONFIG_ADMIN=/path/to/your/adminclusterkubeconfig
     $ export KUBECONFIG_MANAGED1=/path/to/your/managedclusterkubeconfig

     # Lists the contexts in each kubeconfig file
     $ kubectl --kubeconfig $KUBECONFIG_ADMIN config get-contexts -o=name
     my-admin-cluster-context
     some-other-cluster-context

     $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 config get-contexts -o=name
     my-managed-cluster-context
     some-other-cluster2-context

     # Choose the right context name for your admin and managed clusters from the output shown and set the KUBECONTEXT
     # environment variables
     $ export KUBECONTEXT_ADMIN=<admin-cluster-context-name>
     $ export KUBECONTEXT_MANAGED1=<managed-cluster-context-name>
     ```

For detailed instructions on how to install and customize Verrazzano on a Kubernetes cluster using a specific profile,
see the [Installation Guide]({{< relref "/docs/setup/install/installation.md" >}}) and [Installation Profiles]({{< relref "/docs/setup/install/profiles.md" >}}).

### Cluster label selection

You can provide a label selector in the Verrazzano resource.
The label selector is used to determine which clusters created in Rancher will be automatically registered by Verrazzano.

#### Verrazzano configuration for cluster label selection

The following illustrates an admin cluster Verrazzano resource that has been configured to support cluster label selection.
```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: admin
spec:
  profile: prod
  components:
    clusterOperator:
      overrides:
      - values:
          syncRancherClusters:
            enabled: true
            clusterSelector:
              matchExpressions:Ï
              - key: verrazzanomulticluster
                operator: In
                values: [supported]
```


- If `enabled` is set to `false` (the default), then no clusters created in Rancher will be automatically registered by Verrazzano.
- If the field is not explicitly set, then no Rancher clusters will be automatically registered.
- If `enabled` is explicitly set to `true`, then Verrazzano will automatically register clusters created in Rancher that match the `clusterSelector` field.
  - The `clusterSelector` field implements a [LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/{{<kubernetes_api_version>}}/#labelselector-v1-meta).
  - Any cluster created with a label that matches the `clusterSelector` will be automatically registered by Verrazzano.
  - If the `clusterSelector` field is omitted, then all clusters created in Rancher will be automatically registered.


## Preregistration

Use the following instructions to obtain the Kubernetes API server address for the admin cluster.
This address must be accessible from the managed cluster.
- [Most Kubernetes clusters](#most-kubernetes-clusters)
- [Kind clusters](#kind-clusters)

  #### Most Kubernetes clusters

  For most types of Kubernetes clusters, except for Kind clusters, you can find the externally accessible API server
  address of the admin cluster from its kubeconfig file.

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
  In the output of this command, you will find the URL of the admin cluster API server in the `server` field. Set the
  value of the `ADMIN_K8S_SERVER_ADDRESS` variable to this URL.
  ```
  $ export ADMIN_K8S_SERVER_ADDRESS=<the server address from the config output>
  ```

  #### Kind clusters

  Kind clusters run within a Docker container. If your admin and managed clusters are Kind clusters, then the API server
  address of the admin cluster in its kubeconfig file is typically a local address on the host machine, which will not be
  accessible from the managed cluster. Use the `kind` command to obtain the `internal` kubeconfig of the admin
  cluster, which will contain a server address accessible from other Kind clusters on the same machine, and therefore in
  the same Docker network.

  ```
  $ kind get kubeconfig --internal --name <your-admin-cluster-name> | grep server
  ```
  In the output of this command, you can find the URL of the admin cluster API server in the `server` field. Set the
  value of the `ADMIN_K8S_SERVER_ADDRESS` variable to this URL.
  ```
  $ export ADMIN_K8S_SERVER_ADDRESS=<the server address from the config output>
  ```

On the admin cluster, create a ConfigMap that contains the externally accessible admin cluster Kubernetes server
address found in the previous step.
To be detected by Verrazzano, this ConfigMap must be named `verrazzano-admin-cluster`.
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

## Register the managed cluster

There are two methods by which you can register Verrazzano clusters.
These methods are interchangeable and synchronized, so you can use either one to achieve the same result.
- [Register using Rancher](#register-using-rancher)
- [Register using VerrazzanoManagedCluster](#registration-through-vmc)

If Rancher is not enabled, then refer to [Verrazzano multicluster installation without Rancher]({{< relref "docs/setup/install/multicluster-no-rancher.md" >}})
because additional steps will be required to register a managed cluster.

### Register using Rancher

To register a cluster using Rancher, see [Setting up Kubernetes Clusters in Rancher](https://docs.ranchermanager.rancher.io/pages-for-subheaders/kubernetes-clusters-in-rancher-setup).
Verrazzano will manage all clusters whose labels match the [cluster label selector](#cluster-label-selection).

### Register using VerrazzanoManagedCluster

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
   EOF
   ```
2. Wait for the VerrazzanoManagedCluster resource to reach the `Ready` status. At that point, it will have generated a YAML
   file that must be applied on the managed cluster to complete the registration process.

   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       wait --for=condition=Ready \
       vmc managed1 -n verrazzano-mc
   ```

3. Apply the Rancher registration manifest from the Rancher console.


   a. In the Rancher menu, under `GLOBAL APPS`, navigate to `Cluster Management`.


   b. Select the cluster with the same name as the VerrazzanoManagedCluster resource that you just created.


   c. Under the `Registration` tab of the cluster view, select the registration command for the managed cluster.


   d. Using the registration information in the Rancher console, from the managed cluster, apply a command using this format.
   ```
   kubectl apply --kubeconfig $KUBECONFIG_MANAGED1 --context $KUBECONTEXT_MANAGED1 -f https://<Rancher-console-url>/v3/import/<Rancher-registration>.yaml
   ```

## Verify that managed cluster registration has completed
You can perform all the verification steps on the admin cluster.

1. Verify that the managed cluster can connect to the admin cluster. View the status of the `VerrazzanoManagedCluster`
   resource on the admin cluster, and check whether the `lastAgentConnectTime`, `prometheusHost`, and `apiUrl` fields are
   populated. This may take up to two minutes after completing the registration steps.
   ```
   # On the admin cluster
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
       get vmc managed1 -n verrazzano-mc -o yaml

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
   View the Rancher UI on the admin cluster. If the registration with Rancher was successful, then your cluster will be
   listed in Rancher's list of clusters, and will be in `Active` state. You can find the Rancher UI URL for your
   cluster by following the instructions for [Accessing Verrazzano]({{< relref "/docs/access/_index.md" >}}).

### Verify that managed cluster metrics are being collected

Verify that the admin cluster is collecting metrics from the managed cluster.  The Prometheus output will include
records that contain the name of the Verrazzano cluster (labeled as `verrazzano_cluster`).

You can find the Prometheus UI URL for your cluster by following the instructions for [Accessing Verrazzano]({{< relref "/docs/access/_index.md" >}}).
Run a query for a metric (for example, `node_disk_io_time_seconds_total`).

**Sample output of a Prometheus query**

![Prometheus](/docs/images/multicluster/prometheus-multicluster.png)

An alternative approach to using the Prometheus UI is to query metrics from the command line. Here is an example of how to obtain Prometheus metrics from the command line. Search the output of the query for responses that have the `verrazzano_cluster` field set to the name of the managed cluster.
   ```
   # On the admin cluster
   $ prometheusUrl=$(kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
                    get verrazzano -o jsonpath='{.items[0].status.instance.prometheusUrl}')
   $ VZPASS=$(kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
              get secret verrazzano --namespace verrazzano-system \
              -o jsonpath={.data.password} | base64 --decode; echo)
   $ curl -k --user verrazzano:${VZPASS} "${prometheusUrl}/api/v1/query?query=node_disk_io_time_seconds_total"
   ```

### Verify that managed cluster logs are being collected

Verify that the admin cluster is collecting logs from the managed cluster.  The output will include records which have the name of the managed cluster in the `cluster_name` field.

You can find the OpenSearch Dashboards URL for your cluster by following the instructions for [Accessing Verrazzano]({{< relref "/docs/access/_index.md" >}}).
Searching the `verrazzano-system` data stream for log records with the `cluster_name` set to the managed cluster name yields logs for the managed cluster.

**Sample output of a OpenSearch Dashboards screen**

![OpenSearch Dashboards](/docs/images/multicluster/opensearch-multicluster.png)

An alternative approach to using the OpenSearch Dashboards is to query OpenSearch from the command line.  Here is an example of how to obtain log records from the command line.  Search the output of the query for responses that have the `cluster_name` field set to the name of the managed cluster.
   ```
   # On the admin cluster
   $ OS_URL=$(kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
                    get verrazzano -o jsonpath='{.items[0].status.instance.openSearchUrl}')
   $ VZPASS=$(kubectl --kubeconfig $KUBECONFIG_ADMIN --context $KUBECONTEXT_ADMIN \
              get secret verrazzano --namespace verrazzano-system \
              -o jsonpath={.data.password} | base64 --decode; echo)
   $ curl -k --user verrazzano:${VZPASS} -X POST -H 'kbn-xsrf: true' "${OS_URL}/verrazzano-system/_search?size=25"
   ```

## Run applications in multicluster Verrazzano

The Verrazzano multicluster setup is now complete and you can deploy applications by following the [Multicluster Hello World Helidon]({{< relref "/docs/samples/multicluster/hello-helidon/_index.md" >}}) example application.

## Use the admin cluster UI

The admin cluster serves as a central point from which to register and deploy applications to managed clusters.

In the Verrazzano UI on the admin cluster, you can view the following:

- The managed clusters registered with this admin cluster.
- VerrazzanoProjects located on this admin cluster or any of its registered managed clusters, or both.
- Applications located on this admin cluster or any of its registered managed clusters, or both.
