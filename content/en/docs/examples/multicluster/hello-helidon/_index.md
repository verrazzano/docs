---
title: "Multicluster Hello World Helidon"
linktitle: "Hello World Helidon"
weight: 1
aliases:
  - /docs/samples/multicluster/hello-helidon
---

The Hello World Helidon example is a Helidon-based service that returns a "Hello World" response when invoked. The example application is specified using Open Application Model (OAM) component and application configuration YAML files, and then deployed by applying those files. The example also demonstrates how to change the placement of the application to a different cluster.
.

## Before you begin

Create a multicluster Verrazzano installation with one admin and one managed cluster, and register the managed cluster, by following the instructions [here]({{< relref "/docs/setup/mc-install/multicluster.md" >}}).

Set up the following environment variables to point to the kubeconfig file for the admin and managed clusters.
{{< clipboard >}}
<div class="highlight">

```
$ export KUBECONFIG_ADMIN=/path/to/your/adminclusterkubeconfig
$ export KUBECONFIG_MANAGED1=/path/to/your/managedclusterkubeconfig
```

</div>
{{< /clipboard >}}

**NOTE**:  The Hello World Helidon application deployment files are contained in the Verrazzano project located at
`<VERRAZZANO_HOME>/examples/multicluster/hello-helidon`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.


## Create the application namespace

Apply the VerrazzanoProject resource on the admin cluster that defines the namespace for the application.  The namespaces defined in the VerrazzanoProject resource will be created on the admin cluster and all the managed clusters.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/hello-helidon/verrazzano-project.yaml >}}
   ```

</div>
{{< /clipboard >}}

## Deploy the application

1. Apply the `hello-helidon` multicluster application configuration resource to deploy the application.  The multicluster resource is an envelope that contains an OAM resource and a list of clusters to which to deploy.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/hello-helidon/hello-helidon-comp.yaml >}}
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/hello-helidon/mc-hello-helidon-app.yaml >}}
   ```

</div>
{{< /clipboard >}}

1. Wait for the application to be ready on the managed cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 wait \
       --for=condition=Ready pods \
       --all -n hello-helidon \
       --timeout=300s
   ```

</div>
{{< /clipboard >}}


## Explore the example application

Follow the instructions for [exploring]({{< relref "/docs/examples/hello-helidon/#explore-the-application" >}}) the Hello World Helidon application in a single cluster use case. Use the managed cluster kubeconfig file for testing the example application.

## Verify the deployed application

Follow the instructions for [troubleshooting]({{< relref "/docs/examples/hello-helidon/#troubleshooting" >}}) the Hello World Helidon application in a single cluster use case. Use the managed cluster kubeconfig file for troubleshooting the example application.

1. Verify that the application namespace exists on the managed cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get namespace hello-helidon
   ```

</div>
{{< /clipboard >}}

1. Verify that the multicluster resource for the application exists.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get MultiClusterApplicationConfiguration -n hello-helidon
   ```

</div>
{{< /clipboard >}}

## Locating the application on a different cluster

By default, the application is located on the managed cluster called `managed1`. You can change the application's location to be on a different cluster, which can be the admin cluster or a different managed cluster. In this example, you change the placement of the application to the admin cluster by patching the multicluster resources.

1. To change the application's location to the admin cluster, specify the change placement patch file.
{{< clipboard >}}
<div class="highlight">

   ```
   # To change the placement to the admin cluster
   $ export CHANGE_PLACEMENT_PATCH_FILE="{{< release_source_url raw=true path=examples/multicluster/hello-helidon/patch-change-placement-to-admin.yaml >}}"
   ```

</div>
{{< /clipboard >}}

   This environment variable is used in subsequent steps.

1. To change its placement, patch the `hello-helidon` multicluster application configuration.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN patch mcappconf hello-helidon-appconf \
       -n hello-helidon \
       --type merge \
       --patch "$(curl -s $CHANGE_PLACEMENT_PATCH_FILE)"

   # Expected response
   multiclusterapplicationconfiguration.clusters.verrazzano.io/hello-helidon-appconf patched
   ```

</div>
{{< /clipboard >}}

1. To verify that its placement has changed, view the multicluster resource.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN get mcappconf hello-helidon-appconf \
       -n hello-helidon \
       -o jsonpath='{.spec.placement}';echo

   # Expected response
   {"clusters":[{"name":"local"}]}
   ```

</div>
{{< /clipboard >}}

   The cluster
      name, `local`, indicates placement in the admin cluster.

1. To change its placement, patch the VerrazzanoProject.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN patch vp hello-helidon \
       -n verrazzano-mc \
       --type merge \
       --patch "$(curl -s $CHANGE_PLACEMENT_PATCH_FILE)"

   # Expected response
   verrazzanoproject.clusters.verrazzano.io/hello-helidon patched
   ```

</div>
{{< /clipboard >}}

1. Wait for the application to be ready on the admin cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN wait \
       --for=condition=Ready pods \
       --all -n hello-helidon \
       --timeout=300s
   ```

</div>
{{< /clipboard >}}

   **NOTE**: If you are returning the application to the managed cluster, then instead, wait for the application to be
   ready on the managed cluster.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 wait \
       --for=condition=Ready pods \
       --all -n hello-helidon \
       --timeout=300s
   ```

</div>
{{< /clipboard >}}

1. Now, you can test the example application running in its new location.

   To return the application to the managed cluster named `managed1`, set the value of the `CHANGE_PLACEMENT_PATCH_FILE` environment variable to the patch file provided for that purpose, then repeat the previous numbered steps.
{{< clipboard >}}
<div class="highlight">

   ```
   # To change the placement back to the managed cluster named managed1
   $ export CHANGE_PLACEMENT_PATCH_FILE="{{< release_source_url raw=true path=examples/multicluster/hello-helidon/patch-return-placement-to-managed1.yaml >}}"
   ```

</div>
{{< /clipboard >}}

## Undeploy the application

Regardless of its location, to undeploy the application,
delete the application resources and the project from the admin cluster.
Undeploy affects all clusters in which the application is located.

1. To undeploy the application, delete the Hello World Helidon OAM resources.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
       -f {{< release_source_url raw=true path=examples/multicluster/hello-helidon/mc-hello-helidon-app.yaml >}}
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
       -f {{< release_source_url raw=true path=examples/multicluster/hello-helidon/hello-helidon-comp.yaml >}}
   ```

</div>
{{< /clipboard >}}


1. Delete the project.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
       -f {{< release_source_url raw=true path=examples/multicluster/hello-helidon/verrazzano-project.yaml >}}
   ```

</div>
{{< /clipboard >}}


1. Delete the namespace `hello-helidon` after the application pod is terminated.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete namespace hello-helidon
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 delete namespace hello-helidon
   ```

</div>
{{< /clipboard >}}
