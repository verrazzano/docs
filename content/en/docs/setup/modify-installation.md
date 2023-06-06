---
title: "Modify Verrazzano Installations"
description: "Modify and customize Verrazzano installations"
weight: 5
draft: false
aliases:
  - /docs/install/modify-installation
---

This document shows how you can modify Verrazzano to add customizations to your installation.

## Verrazzano resource

The Verrazzano resource controls the installation of Verrazzano in a cluster.
The life cycle of this custom resource controls the life cycle of Verrazzano.
You can apply customizations to Verrazzano by modifying the specification of this resource.
The following is an example of a Verrazzano resource without extra configurations.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
```

</div>
{{< /clipboard >}}

## Edit the Verrazzano resource

The following sections show you how to modify the Verrazzano resource.

### Pre-Installation

Before you install Verrazzano, you can define a Verrazzano resource manifest file that can be supplied at installation time.
The following is an example of a Verrazzano manifest file that enables two Verrazzano components, `argoCD` and `velero`, that are disabled by default.

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
    velero:
      enabled: true
```

</div>
{{< /clipboard >}}

You can save this manifest file and supply it to the Verrazzano CLI at installation time.

{{< clipboard >}}
<div class="highlight">

```
$ vz install -f verrazzano.yaml
```

</div>
{{< /clipboard >}}

For detailed installation instructions, see the [Install Guide]({{< relref "/docs/setup/install/" >}}).

### Post-Installation

Also, you can modify the Verrazzano resource _after_ it has been installed.
Updates to the Verrazzano resource will be reflected in the cluster.
You must get the name of the Verrazzano resource to be able to edit it in the cluster.
Verrazzano allows only one custom resource to exist per cluster.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl get vz -A
```
```
# Sample output
NAMESPACE   NAME                 AVAILABLE   STATUS            VERSION
default     example-verrazzano   24/24       InstallComplete   1.5.0
```

</div>
{{< /clipboard >}}

After you have the name of the Verrazzano resource, you can edit its manifest file.
The `kubectl edit` command lets you directly edit any API resource on the cluster.
For more information on `kubectl edit`, see the [kubectl edit documentation](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#edit).

The following example edits the Verrazzano resource found in the previous sample output.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl edit vz example-verrazzano
```

</div>
{{< /clipboard >}}

## Customization options

Verrazzano supplies a variety of customization options.

The following section illustrates a generic overview of the customization options available using the
[Verrazzano API]({{< relref "/docs/reference/vpo-verrazzano-v1beta1" >}}).

### Component features

Each component has two main fields, `enabled` and `overrides`.

- The `enabled` field lets you selectively install components with the Verrazzano installation.
- The `overrides` field lets you supply custom value overrides to the underlying Helm charts for that component.

The format of these fields is as follows.

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
      overrides:
      - values:
          global:
            podLabels:
              example: label
```

</div>
{{< /clipboard >}}
