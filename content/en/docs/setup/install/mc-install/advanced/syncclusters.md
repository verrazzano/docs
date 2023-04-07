---
title: "Enable syncClusters"
description: "Learn how to enable `syncClusters` and customize your cluster selection"
weight: 1
draft: false
---

You can use `syncClusters` to synchronize cluster registration across Verrazzano. So, any clusters imported in the Rancher console will be synchronized across the rest of Verrazzano, including in Verrazzano managed cluster resources, Rancher, and Argo CD.

Optionally, to customize your cluster selection, you can provide a label selector in the Verrazzano resource.
<br>The label selector is used to determine which clusters imported into Rancher will be automatically registered by Verrazzano.
This helps you to select specific clusters you want to automatically synchronize across the rest of Verrazzano, including in Verrazzano managed cluster resources, Rancher, and Argo CD.

The following illustrates an admin cluster Verrazzano resource that has been configured to use `syncClusters` and set a label selector.
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

The `enabled` field must be set to `true` to use cluster label selection. Verrazzano will automatically register all clusters with labels that match the `clusterSelector` field.
  - The `clusterSelector` field is optional.
  - If `enabled` is set to `true` and the `clusterSelector` field is omitted, then all clusters imported into Rancher will be automatically registered.
  - If `enabled` is set to `false` (the default), then _no_ clusters imported into Rancher will be automatically registered by Verrazzano.
