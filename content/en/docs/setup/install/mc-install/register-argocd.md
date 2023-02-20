---
title: "Register Argo CD"
description: "How to register Argo CD in a multicluster Verrazzano environment"
weight: 2
draft: false
---

## Prerequisites

- Make sure you have completed the steps in the Prerequisites and Install Verrazzano sections in [Install Multicluster Verrazzano]({{< relref "/docs/setup/install/mc-install/multicluster.md" >}}).
- [Enable Argo CD](#enable-argo-cd).

### Enable Argo CD

To use Argo CD in a multicluster Verrazzano environment, you must first enable it on the admin cluster.
Argo CD is _not_ enabled by default, use the following example to enable it using the `dev` installation profile.
{{< clipboard >}}
<div class="highlight">

```
$ vz install -f - <<EOF
  apiVersion: install.verrazzano.io/v1beta1
  kind: Verrazzano
  metadata:
    name: example-verrazzano
  spec:
    profile: dev
    components:    
      argoCD:
        enabled: true
EOF
```
</div>
{{< /clipboard >}}


## Overview

In a multicluster Verrazzano environment, Argo CD integration depends on Rancher being set up. If Rancher is _enabled_, Rancher will be installed before Argo CD and the Argo CD cluster registration will be successful. If Rancher is _disabled_, Argo CD will be installed, however, the Argo CD cluster registration will not be complete until Rancher is installed.

## Refresh the Rancher API token

In the cluster operator's helm chart, you can update the configurable `ARGOCD_CLUSTER_TOKEN_TTL` token's `argoCDClusterTokenTTL` value. By default, the TTL value is set to 240 minutes. In the controller, override the Argo CD token's TTL to 600 minutes.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:
    argoCD:
      enabled: true
    clusterOperator:
      overrides:
        - values:
            argoCDClusterTokenTTL: 600
```

</div>
{{< /clipboard >}}

## Deregister a cluster in Argo CD

To deregister a cluster in Argo CD, deregister the managed cluster. See [Deregister a managed cluster]({{< relref "/docs/setup/install/mc-install/multicluster#deregister-a-managed-cluster" >}}).
