---
title: "Register Argo CD"
description: "How to register Argo CD in a multicluster Verrazzano environment"
weight: 5
draft: false
---

## Prerequisites

- Make sure you have completed the steps in the Prerequisites and Install Verrazzano sections in [Install Multicluster Verrazzano]({{< relref "/docs/setup/install/multicluster.md" >}}).
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

In a multicluster Verrazzano environment, Argo CD integration depends on Rancher being set up. If Rancher is enabled, it will be installed before Argo CD.


## Refresh the Rancher API token

Add a configurable `ARGOCD_CLUSTER_TOKEN_TTL` token in the cluster operator's helm chart, where the default is to 240 minutes. In the controller, we will update the token periodically by checking the token's `created` or `ExpiresAt` value.

{{< clipboard >}}
<div class="highlight">

```
- name: ARGOCD_CLUSTER_TOKEN_TTL
  value: "{{ .Values.argoCDClusterTokenTTL }}"
```
  </div>
  {{< /clipboard >}}

{{< clipboard >}}
<div class="highlight">

```
  # TTL in minutes
  argoCDClusterTokenTTL: 240

```
  </div>
  {{< /clipboard >}}


To override the Argo CD token's TTL:   

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

**Note**: To deregister a cluster in Argo CD, deregister the managed cluster. See [Deregister a managed cluster]({{< relref "/docs/setup/install/multicluster#deregister-a-managed-cluster" >}}).
