---
title: VerrazzanoProject
linkTitle: "VerrazzanoProject"
weight: 4
draft: false
---
The [VerrazzanoProject]({{< relref "/docs/reference/vao-clusters-v1alpha1#clusters.verrazzano.io/v1alpha1.VerrazzanoProject" >}}) custom resource is used to create the application namespaces and their associated security settings on one or more clusters.  The namespaces are always created on the admin cluster.  Here is a sample VerrazzanoProject that specifies a namespace to create on the cluster named `managed1`.

{{< clipboard >}}
<div class="highlight">

    apiVersion: clusters.verrazzano.io/v1alpha1
    kind: VerrazzanoProject
    metadata:
      name: hello-helidon
      namespace: verrazzano-mc
    spec:
      template:
        namespaces:
          - metadata:
              name: hello-helidon
      placement:
        clusters:
          - name: managed1

</div>
{{< /clipboard >}}
