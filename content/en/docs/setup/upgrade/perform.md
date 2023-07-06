---
title: "Perform the Verrazzano Upgrade"
description: "Upgrade Verrazzano"
weight: 2
draft: false
aliases:
  - \docs\upgrade\upgrade
---


It is important to distinguish between updating the Verrazzano platform operator versus upgrading the Verrazzano installation.
The platform operator contains the newer component charts and image versions, so it must be updated prior to upgrading the installation.
Updating the platform operator has no effect on an existing installation until you initiate the Verrazzano installation upgrade.
Currently, there is no way to roll back either the platform operator update or the Verrazzano installation upgrade.  

You can upgrade Verrazzano using the  [Verrazzano CLI]({{< relref "/docs/setup/install" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/).
See the following respective sections.

{{< alert title="NOTE" color="primary" >}}For optimal functionality, be sure to install or upgrade the CLI version to match the Verrazzano version to which you are upgrading.   
{{< /alert >}}

- [Upgrade Verrazzano using the CLI](#upgrade-verrazzano-using-the-cli)
- [Upgrade using kubectl](#upgrade-using-kubectl)

## Upgrade Verrazzano using the CLI

In one simple step, you can upgrade to a specified version of Verrazzano using this command.

1. Update the `Verrazzano` resource to the desired version.

   To update to the latest version (default):
{{< clipboard >}}
<div class="highlight">

   ```
   $ vz upgrade
   ```
</div>
{{< /clipboard >}}

   To update to a specific version, where `<version>` is the desired version:

   {{< clipboard >}}
   <div class="highlight">

  ```
  $ vz upgrade --version <version>
  ```
   </div>
   {{< /clipboard >}}


2. Wait for the upgrade to complete.
   Upgrade logs will be streamed to the command window until the upgrade has completed
   or until the default timeout (30m) has been reached.

## Upgrade using kubectl

Upgrading an existing Verrazzano installation is a two-step process:

* Update the Verrazzano platform operator to the [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/) to which you want to upgrade.
* Upgrade the Verrazzano installation.  

### Update the Verrazzano platform operator
In order to upgrade an existing Verrazzano installation, you must first update the [Verrazzano platform operator](https://github.com/verrazzano/verrazzano).

1. Update the Verrazzano platform operator.

   **NOTE**: If you are using a private container registry, then to update the platform operator, follow the instructions at [Use a Private Registry]({{< relref "/docs/setup/private-registry/private-registry.md" >}}).

   To update to the latest version:
  {{< clipboard >}}
  <div class="highlight">

   ```
   $ kubectl apply -f {{<release_asset_operator_url verrazzano-platform-operator.yaml>}}
   ```
  </div>
  {{< /clipboard >}}


   To update to a specific version, where `<version>` is the desired version:
{{< clipboard >}}
<div class="highlight">

   ```
   # To update to the desired version:
   $ kubectl apply -f https://github.com/verrazzano/verrazzano/releases/download/<version>/verrazzano-platform-operator.yaml
   ```
</div>
{{< /clipboard >}}

2. Wait for the deployment to complete.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator
   ```
   ```
   # Expected response
   deployment "verrazzano-platform-operator" successfully rolled out
   ```
</div>
{{< /clipboard >}}

3. Confirm that the operator pod is correctly defined and running.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl -n verrazzano-install get pods
   ```
   ```
   # Sample output
   NAME                                            READY   STATUS    RESTARTS   AGE
   verrazzano-platform-operator-59d5c585fd-lwhsx   1/1     Running   0          114s
   ```
</div>
{{< /clipboard >}}
### Upgrade Verrazzano

To upgrade the Verrazzano installation, you need to change the version of your installed Verrazzano resource to the version supported by the
Verrazzano platform operator.

**NOTE**: You may only change the `version` field during an upgrade; changes to other fields or component configurations are not supported at this time.

In one simple step, you can upgrade to a specified version of Verrazzano using this command.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl patch vz example-verrazzano -p '{"spec":{"version":"{{<release_version>}}"}}' --type=merge
   ```
</div>
{{< /clipboard >}}

Alternatively, you can upgrade the Verrazzano installation using the following steps.
1. Update the `Verrazzano` resource to the desired version.

      To upgrade the Verrazzano components, you must update the `version` field in your `Verrazzano` resource spec to
      match the version supported by the platform operator to which you upgraded and apply it to the cluster.

      The value of the `version` field in the resource spec must be a [Semantic Versioning](https://semver.org/) value
      corresponding to a valid [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/).

      To update the resource, do one of the following:

      a. Edit the YAML file you used to install Verrazzano and set the `version` field to the latest version.

      For example, to upgrade to `{{<release_version>}}`, your YAML file should be edited to add or update the `version` field.
{{< clipboard >}}

  ```yaml
  apiVersion: install.verrazzano.io/v1beta1
  kind: Verrazzano
  metadata:
    name: example-verrazzano
  spec:
     profile: dev
     version: {{<release_version>}}
  ```

{{< /clipboard >}}

   Then, apply the resource to the cluster (if you have not edited the resource in-place using `kubectl edit`).
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl apply -f example-verrazzano.yaml
   ```
</div>
{{< /clipboard >}}
b. Edit the `Verrazzano` resource directly using `kubectl` and set the `version` field directly, for example:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl edit verrazzano example-verrazzano
   # In the resource editor, add or update the version field to "version: {{<release_version>}}", then save.
   ```
</div>
{{< /clipboard >}}
1. Wait for the upgrade to complete.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl wait \
       --timeout=30m \
       --for=condition=UpgradeComplete verrazzano/example-verrazzano
   ```
</div>
{{< /clipboard >}}
