---
title: "Customize Cluster Selection"
description: "How to customize your cluster selection"
weight: 2
draft: false
---
You can provide a label selector in the Verrazzano resource. The label selector is used to determine which clusters imported into Rancher will be automatically registered by Verrazzano.
This helps you to select specific clusters you automatically want to be synchronized across the rest of Verrazzano, including in Verrazzano managed cluster resources, Rancher, and Argo CD.

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

- If `enabled` is set to `false` (the default), Verrazzano will _not_ synchronize the registration of clusters across Verrazzano, Rancher, and Argo CD.
- If `enabled` is set to `true`, Verrazzano will synchronize the registration of clusters across Verrazzano, Rancher, and Argo CD.
