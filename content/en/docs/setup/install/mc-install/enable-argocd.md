---
title: "Enable Argo CD"
description: "How to enable Argo CD in a multicluster Verrazzano environment"
weight: 2
draft: false
---

In a multicluster Verrazzano environment, Argo CD integration depends on Rancher being enabled on the admin cluster. Argo CD connects to the Rancher proxy to create the required resources for Argo CD cluster registration. By registering managed clusters with Argo CD, after you set up an application in the Argo CD console, those registered clusters will be available for you to select, deploy, and manage applications.

## Prerequisites

- Make sure you have completed the steps in the Prerequisites and Install Verrazzano sections in [Install Multicluster Verrazzano]({{< relref "/docs/setup/install/mc-install/multicluster.md" >}}).

## Enable Argo CD

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
