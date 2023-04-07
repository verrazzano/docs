---
title: "Register Managed Clusters Automatically"
description: "You can synchronize cluster registration across Verrazzano by enabling `syncClusters` in the Verrazzano custom resource."
weight: 1
draft: false
---

## Enable `syncClusters`

You can synchronize cluster registration across Verrazzano by enabling `syncClusters` in the Verrazzano custom resource. So, any clusters imported in the Rancher console will be synchronized across the rest of Verrazzano, including in Verrazzano managed cluster resources, Rancher, and Argo CD.

The following illustrates an admin cluster Verrazzano resource that has been configured to use `syncClusters`.
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

```

</div>
{{< /clipboard >}}

- If `enabled` is set to `false` (the default), Verrazzano will not synchronize the registration of clusters across Verrazzano, Rancher, and Argo CD.
- If `enabled` is set to true, Verrazzano will synchronize the registration of clusters across Verrazzano, Rancher, and Argo CD.

## Customize Cluster Selection

Optionally, to customize your cluster selection, you can provide a label selector in the Verrazzano resource.
<br>The label selector is used to determine which clusters imported into Rancher will be automatically registered by Verrazzano.
This helps you to select specific clusters you want to automatically synchronize across the rest of Verrazzano, including in Verrazzano managed cluster resources, Rancher, and Argo CD.

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

The `enabled` field must be set to `true` to use cluster label selection. Verrazzano will automatically register all clusters with labels that match the `clusterSelector` field.
  - The `clusterSelector` field is optional.
  - If `enabled` is set to `true` and the `clusterSelector` field is omitted, then all clusters imported into Rancher will be automatically registered.
  - If `enabled` is set to `false` (the default), then _no_ clusters imported into Rancher will be automatically registered by Verrazzano.
