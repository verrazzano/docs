---
title: "Synchronize Managed Clusters Registration"
description: ""
weight: 3
draft: false
aliases:
  - /docs/setup/install/mc-install/advanced/syncclusters
---

You can synchronize cluster registration across Verrazzano by enabling `syncClusters` in the Verrazzano custom resource. Any clusters imported in the Rancher console will be synchronized across the rest of Verrazzano, including in Verrazzano managed cluster resources, Rancher, and Argo CD. Additionally, you can use a [label selector](#filter-cluster-selection) to filter the clusters you want registered.

## Register managed clusters automatically

The following illustrates an admin cluster Verrazzano resource that enables `syncClusters`.
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

- When `enabled` is set to true, Verrazzano will synchronize the registration of clusters across Verrazzano, Rancher, and Argo CD.
- If `enabled` is set to `false` (the default), then Verrazzano will not synchronize the registration of clusters across Verrazzano.

## Filter cluster selection

Optionally, to determine which clusters imported into Rancher will be automatically registered by Verrazzano, you can provide a label selector in the Verrazzano resource.
This lets you filter which clusters you want to be synchronized.

The following illustrates an admin cluster Verrazzano resource that supports cluster label selection.
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

The `syncClusters` `enabled` field must be set to `true` to use cluster label selection. Verrazzano will automatically register all clusters with labels that match the `clusterSelector` field.
  - The `clusterSelector` field is optional.
  - If `enabled` is set to `true` and the `clusterSelector` field is omitted, then all clusters imported into Rancher will be automatically registered.

When you import a cluster into Rancher, you can provide a `label` and `value` for the cluster. If the label matches this label selector, then the cluster will be synchronized.
