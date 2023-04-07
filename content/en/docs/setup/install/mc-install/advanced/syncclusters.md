---
title: "Synchronize Managed Clusters Registration"
description: "Learn how to synchronize and filter cluster registration"
weight: 1
draft: false
---

You can synchronize cluster registration automatically across Verrazzano by enabling `syncClusters` in the Verrazzano custom resource. Any clusters imported in the Rancher console then will be synchronized across the rest of Verrazzano, including in Verrazzano managed cluster resources, Rancher, and Argo CD. Additionally, you can filter the clusters you want to be synchronized by using a label selector.

## Enable `syncClusters`

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

- If `enabled` is set to `false` (the default), Verrazzano will not synchronize the registration of clusters across Verrazzano.
- If `enabled` is set to true, Verrazzano will synchronize the registration of clusters across Verrazzano, Rancher, and Argo CD.

## Filter cluster selection

Optionally, to determine which clusters imported into Rancher will be automatically registered by Verrazzano, you can provide a label selector in the Verrazzano resource.
This lets you filter which clusters you want synchronized.

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
  - If `enabled` is set to `false` (the default), then _no_ clusters imported into Rancher will be automatically registered by Verrazzano.
