---
title: "Customize Cluster Selection"
description: "Learn how to customize your cluster selection"
weight: 2
draft: false
---
You can provide a label selector in the Verrazzano resource. The label selector is used to determine which clusters created in Rancher will be automatically registered by Verrazzano.

The following illustrates an admin cluster Verrazzano resource that has been configured to support cluster label selection.
{{< clipboard >}}
<div class="highlight">

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
          syncClusters:
            enabled: true
            clusterSelector:
              matchExpressions:
              - key: verrazzanomulticluster
                operator: In
                values: [supported]
```

</div>
{{< /clipboard >}}

- If `enabled` is set to `false` (the default), then no clusters created in Rancher will be automatically registered by Verrazzano.
- If `enabled` is explicitly set to `true`, then Verrazzano will automatically register clusters created in Rancher with labels that match the `clusterSelector` field.
  - The `clusterSelector` field is optional. If it is omitted, then all clusters created in Rancher will be automatically registered.
  - The `clusterSelector` field implements a [LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/{{<kubernetes_api_version>}}/#labelselector-v1-meta).

**NOTE**: If Argo CD is enabled in Verrazzano, then the label selector also is used by Verrazzano to select the Rancher clusters to automatically register with Argo CD. For more information about using Argo CD with Verrazzano, see [Argo CD]({{< relref "/docs/samples/argo-cd/_index.md" >}}).  
