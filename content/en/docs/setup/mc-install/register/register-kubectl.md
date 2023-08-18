---
title: "Use Kubernetes Custom Resource"
description: "Register managed clusters using `kubectl`"
weight: 2
draft: false
aliases:
  - /docs/setup/install/mc-install/advanced/register-kubectl
---

To register managed clusters using the VerrazzanoManagedCluster resource, complete the following steps:

1. Create the environment variables, `KUBECONFIG_ADMIN`, `KUBECONTEXT_ADMIN`, `KUBECONFIG_MANAGED1`, and
  `KUBECONTEXT_MANAGED1`, and point them to the kubeconfig files and contexts for the admin and managed cluster,
  respectively. You will use these environment variables in subsequent steps when registering the managed cluster. The
  following shows an example of how to set these environment variables.
{{< clipboard >}}
<div class="highlight">

   ```
   $ export KUBECONFIG_ADMIN=/path/to/your/adminclusterkubeconfig
   $ export KUBECONFIG_MANAGED1=/path/to/your/managedclusterkubeconfig

   # Lists the contexts in each kubeconfig file
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN config get-contexts -o=name
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 config get-contexts -o=name

   # Choose the right context name for your admin and managed clusters from the output shown and set the KUBECONTEXT
   # environment variables
   $ export KUBECONTEXT_ADMIN=<admin-cluster-context-name>
   $ export KUBECONTEXT_MANAGED1=<managed-cluster-context-name>
   ```

</div>
{{< /clipboard >}}

2. To begin the registration process for a managed cluster named `managed1`, apply the VerrazzanoManagedCluster resource on the admin cluster.
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
     description: "Test VerrazzanoManagedCluster resource"
   EOF
   ```

</div>
{{< /clipboard >}}

3. Wait for the VerrazzanoManagedCluster resource to reach the `Ready` status. At that point, it will have generated a YAML
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

4. Export the YAML file created to register the managed cluster.
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

5. Apply the registration file exported in the previous step, on the managed cluster.
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
