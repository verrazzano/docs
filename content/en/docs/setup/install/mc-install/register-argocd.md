---
title: "Register Argo CD"
description: "How to register Argo CD in a multicluster Verrazzano environment"
weight: 2
draft: false
---

In a multicluster Verrazzano environment, Argo CD integration depends on Rancher being enabled on the admin cluster. Argo CD uses Rancher to register managed clusters in Argo CD. By registering managed clusters with Argo CD, after you set up an application in the Argo CD console, those registered clusters will be available for you to select, deploy, and manage applications.

## Prerequisites

- Make sure you have completed the steps in the Prerequisites and Install Verrazzano sections in [Install Multicluster Verrazzano]({{< relref "/docs/setup/install/mc-install/multicluster.md" >}}).
- [Enable Argo CD](#enable-argo-cd).

### Enable Argo CD

To use Argo CD in a multicluster Verrazzano environment, you must first enable it on the admin cluster.

Argo CD is _not_ enabled by default, the following example enables it using the `dev` installation profile.

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


## Refresh the Rancher API token

By default, the Argo CD token's TTL is set to 240 minutes. If you want to modify it, you can update the configurable `ARGOCD_CLUSTER_TOKEN_TTL` token's `argoCDClusterTokenTTL` value. The following example show you how to override the Argo CD token's TTL to 600 minutes.

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

## Deregister a cluster

To deregister a cluster in Argo CD, follow the instructions at [Deregister a managed cluster]({{< relref "/docs/setup/install/mc-install/multicluster#deregister-a-managed-cluster" >}}).
