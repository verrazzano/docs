---
title: "Verrazzano in a MultiCluster Environment"
linkTitle: Verrazzano in a MultiCluster Environment
weight: 1
draft: false
---

MultiCluster Verrazzano consists of an `admin` Kubernetes cluster and optionally, one or more `managed` clusters.

The following are key concepts for understanding MultiCluster Verrazzano
1. [Admin Kubernetes Cluster](#admin-kubernetes-cluster)
1. [Managed Kubernetes Clusters](#managed-kubernetes-clusters)
1. [The VerrazzanoProject Resource](#the-verrazzanoproject-resource)
1. [Verrazzano MultiCluster resources](#verrazzano-multicluster-resources)
1. [Managed Cluster Registration](#managed-cluster-registration)
1. [Trying out MultiCluster Verrazzano](#trying-out-multicluster-verrazzano)

The diagram below shows an overview of how MultiCluster Verrazzano works


![](../../images/VerrazzanoMultiCluster.png)

### Admin Kubernetes Cluster
A Verrazzano admin cluster is intended to be a central management point for
- Deploying and undeploying applications to the `managed` clusters registered with this admin cluster
- Viewing logs and metrics for both Verrazzano components and applications that reside in the managed clusters

One or more `managed` clusters may be registered with an admin cluster, by creating a `VerrazzanoManagedCluster`
resource in the `verrazzano-mc` namespace of the admin cluster.

**Note:** The admin cluster will have a fully functional Verrazzano installation, and applications may be placed on it,
as well as on managed clusters.

### Managed Kubernetes Clusters
A Verrazzano managed cluster has a minimal footprint of Verrazzano installed (using the `managed-cluster`
installation profile). A managed cluster has the following additional characteristics:
- It is registered with an admin cluster with a unique name
- Logs for Verrazzano system components and Verrazzano multiCluster applications will be sent to
  Elasticsearch running on the admin cluster, and viewable from that cluster
- A Verrazzano `MultiCluster` Kubernetes resource created on the admin cluster will be retrieved and deployed to a
  managed cluster if all of the following are true:
  - The resource is part of a `VerrazzanoProject` that has a `placement` in this managed cluster 
  - The resource itself has a a `placement` in this managed cluster

### The VerrazzanoProject Resource
A [`VerrazzanoProject`](../../reference/api/multicluster/verrazzanoproject "api docs") provides a way to group application namespaces that are owned or administered by the
same user or group of users. 
- For multicluster applications to work correctly, a VerrazzanoProject containing the application's namespace MUST
  first be created
- A `VerrazzanoProject` resource is created by a Verrazzano administrator user, and specifies the following:
  - A list of namespaces that the project governs
  - A user or group that is designated as the `Project Admin` of the VerrazzanoProject. Project Admins may deploy
    or delete applications and related resources in the namespaces in the project.
  - A user or group that is designated as `Project Monitor` of the VerrazzanoProject. Project Monitors may view 
    the resources in the namespaces in the project, but not modify or delete them.
- The creation of a `VerrazzanoProject` results in the creation of the specified namespaces in the project, if those
  namespaces do not already exist.
- It also results in the creation of a Kubernetes `RoleBinding` in each of the namespaces, to set up the appropriate
  permissions for the Project Admins and Project Monitors of the project.
  
### Verrazzano MultiCluster Resources
Verrazzano includes several `MultiCluster` resource definitions, for resources that may be targeted for placement in a
specified cluster.

1. [MultiClusterApplicationConfiguration](../../reference/api/multicluster/multiclusterapplicationconfiguration "api docs")
1. [MultiClusterComponent](../../reference/api/multicluster/multiclustercomponent "api docs")
1. [MultiClusterConfigMap](../../reference/api/multicluster/multiclusterconfigmap "api docs")
1. [MultiClusterLoggingScope](../../reference/api/multicluster/multiclusterloggingscope "api docs")
1. [MultiClusterSecret](../../reference/api/multicluster/multiclustersecret "api docs")

- Each `MultiCluster` resource type serves as a wrapper for an underlying resource type
- A `MultiCluster` resource additionally allows the `placement` of the underlying resource to be specified as a list of
  cluster names of the clusters in which the resource must be placed.
- `MultiCluster` resources are created in the `admin` cluster, in a namespace that is part of a `VerrazzanoProject`
  and targeted for `placement` in either the local admin cluster, or a remote `managed` cluster.
- A `MultiCluster` resource is said to be part of a `VerrazzanoProject`, if it is in a namespace that is governed 
  by that `VerrazzanoProject`

### Managed Cluster Registration
A `managed` cluster may be registered with an `admin` cluster using a 2-step process.

**Step 1:** Creating a [`VerrazzanoManagedCluster`](../../reference/api/multicluster/verrazzanomanagedcluster "api docs") resource in the `verrazzano-mc` namespace of the `admin` cluster and

**Step 2:** Retrieving the Kubernetes manifest generated in the `VerrazzanoManagedCluster` resource and applying it on 
   the `managed` cluster to complete the registration.
   
When a managed cluster is registered, the following things will start happening.

1. Immediately after the first registration step, the `admin` cluster begins scraping Prometheus metrics from the newly
   registered `managed` cluster
1. After both steps of the registration are complete, the `managed` cluster begins polling the admin cluster for
   `VerrazzanoProject` resources and `MultiCluster` resources which specify a `placement` in this managed cluster.
    1. Any `VerrazzanoProject` resources placed in this managed cluster are retrieved, and the corresponding namespaces 
   and security permissions (`RoleBindings`) are created in the managed cluster.
    1. Any `MultiCluster` resources that are placed in this managed cluster, and are in a `VerrazzanoProject` that is 
       also placed in this managed cluster, are retrieved, and created or updated on the managed cluster. The 
       underlying resource represented by the `MultiCluster` resource is unwrapped and created or updated on the managed
       cluster. The managed cluster namespace of the `MultiCluster` resource and its underlying resource matches 
       the admin cluster namespace of the `MultiCluster` resource.
1. For `MultiClusterApplicationConfigurations` retrieved and unwrapped on a `managed` cluster, the application logs will
   be sent to Elasticsearch on the `admin` cluster, and may be viewed from the Verrazzano-installed Kibana on the 
   admin cluster. Likewise, application metrics will be scraped by the admin cluster and visible in the 
   Verrazzano-installed Prometheus on the admin cluster.

### Trying Out Multicluster Verrazzano
For more information, and to try out multicluster Verrazzano, please refer to the
[API Documentation](../../reference/api/) for the resources described in this page, as well as the
[Hello World Helidon multicluster example application](https://github.com/verrazzano/verrazzano/tree/master/examples/multicluster/hello-helidon)
available in the Verrazzano Github repository.