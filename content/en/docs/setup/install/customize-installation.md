---
title: "Modify Verrazzano Installation"
description: "How to modify a Verrazzano Installation"
weight: 3
draft: false
---

The following instructions show you how to modify Verrazzano to add customizations to your installation.

## Verrazzano resource

The Verrazzano resource controls the installation of Verrazzano on a cluster.
The lifecycle of this custom resource controls the lifecycle of Verrazzano.
You are able to apply customizations to Verrazzano by modifying the spec of this resource.
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

## Editing the Verrazzano resource

The following will demonstrate how to modify the Verrazzano custom resource.

### Pre-Installation

Before you install Verrazzano, you can define a Verrazzano custom resource manifest that can be supplied at install time.
The following is an example of a Verrazzano manifest that enables components that are disabled by default.

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

You can save this manifest to a file and supply it to the Verrazzano CLI at install time.

{{< clipboard >}}
<div class="highlight">

```
vz install -f verrazzano.yaml
```

</div>
{{< /clipboard >}}

Refer to the [installation documentation]({{< relref "/docs/setup/install/installation.md" >}}) for detailed installation instructions.

### Post-Installation

You can modify the Verrazzano custom resource after it has been installed.
Updates to the Verrazzano custom resource will be reflected in the cluster.
You must locate the installed Verrazzano to be able to edit it in cluster.
Verrazzano only allows for one custom resource to exist per cluster.

{{< clipboard >}}
<div class="highlight">

```
kubectl get vz -A
```
```
# Sample output
NAMESPACE   NAME                 AVAILABLE   STATUS            VERSION
default     example-verrazzano   24/24       InstallComplete   1.5.0
```

</div>
{{< /clipboard >}}

Once you have the name of your Verrazzano resource, you can edit its manifest.
The `kubectl edit` command allows you to directly edit any API resource on the cluster.
Refer to the [kubectl edit documentation](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#edit) for more information on `kubectl edit`.
The following example edits the Verrazzano resource found in the sample output.

{{< clipboard >}}
<div class="highlight">

```
kubectl edit vz example-verrazzano
```

</div>
{{< /clipboard >}}

## Customization options

Verrazzano supplies a variety of customization options.
Refer to [Customize Verrazzano]({{< relref "/docs/customize/_index.md" >}}) for or more detail on specific customization
The following demonstrates a generic overview of the customization options available through the [Verrazzano API]({{< relref "/docs/reference/API/vpo-verrazzano-v1beta1.md" >}}).

### Component Features

Each component has two main fields, `enabled` and `overrides`.

- The `enabled` field allows you to selectively install components with the Verrazzano installation.
- The `overrides` field allows you to supply custom value overrides to the underlying Helm charts for that component.

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
