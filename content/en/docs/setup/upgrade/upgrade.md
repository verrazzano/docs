---
title: "Upgrade Guide"
linkTitle: "Upgrade"
description: "How to upgrade Verrazzano"
weight: 9
draft: false
---

Upgrading an existing Verrazzano installation involves:

* Upgrading the Verrazzano platform operator to the [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/) to which you want to upgrade.
* Updating the version of your installed `Verrazzano` resource to the version supported by the upgraded operator.

Performing an upgrade will upgrade only the Verrazzano components related to the existing installation.  Upgrading will
not have any impact on running applications.

**NOTE:** You may only change the version field during an upgrade; changes to other fields or component configurations are not supported at this time.

### Upgrade the Verrazzano platform operator

In order to upgrade an existing Verrazzano installation, you must first upgrade the [Verrazzano platform operator](https://github.com/verrazzano/verrazzano-platform-operator).

1. Upgrade the Verrazzano platform operator.

    To upgrade to the latest version:

    ```shell
    $ kubectl apply -f https://github.com/verrazzano/verrazzano/releases/latest/download/operator.yaml
    ```

   To upgrade to a specific version, where `<version>` is the desired version:

    ```shell
    $ kubectl apply -f https://github.com/verrazzano/verrazzano/releases/download/<version>/operator.yaml
    ```

    For example:

    ```shell
    $ kubectl apply -f https://github.com/verrazzano/verrazzano/releases/download/v0.7.0/operator.yaml
    ```


1. Wait for the deployment to complete.

    ```shell
    $ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator
    deployment "verrazzano-platform-operator" successfully rolled out
    ```

1. Confirm that the operator pod is correctly defined and running.

    ```shell
    $ kubectl -n verrazzano-install get pods
    NAME                                            READY   STATUS    RESTARTS   AGE
    verrazzano-platform-operator-59d5c585fd-lwhsx   1/1     Running   0          114s
    ```

### Upgrade Verrazzano

To upgrade Verrazzano:

1. Update the `Verrazzano` resource to the desired version.

      To upgrade the Verrazzano components, you must update the `version` field in your `Verrazzano` resource spec to
      match the version supported by the platform operator to which you upgraded and apply it to the cluster.

      The value of the `version` field in the resource spec must be a [Semantic Versioning](https://semver.org/) value
      corresponding to a valid [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/).

      You can update the resource by doing one of the following:

      a. Editing the YAML file you used to install Verrazzano and setting the version field to the latest version.

      For example, to upgrade to `v0.7.0`, your YAML file should be edited to add or update the version field:

      ```yaml
      apiVersion: install.verrazzano.io/v1alpha1
      kind: Verrazzano
      metadata:
        name: my-verrazzano
      spec:
        profile: dev
        version: v0.7.0
      ```

      Then apply the resource to the cluster (if you have not edited the resource in-place using `kubectl edit`):

      ```shell
      $ kubectl apply -f my-verrazzano.yaml
      ```

      b. Editing the `Verrazzano` resource directly using `kubectl` and setting the version field directly, for example:

      ```shell
      $ kubectl edit verrazzano my-verrazzano
      # In the resource editor, add or update the version field to "version: v0.7.0", then save.
      ```

1. Wait for the upgrade to complete:

   ```shell
   $ kubectl wait --timeout=20m --for=condition=UpgradeComplete verrazzano/my-verrazzano
   ```

### Verify the upgrade

Check that all the pods in the `verrazzano-system` namespace are in the `Running` state.  While the upgrade is in progress,
you may see some pods terminating and restarting as newer versions of components are applied.

For example:

```
$ kubectl get pods -n verrazzano-system
verrazzano-admission-controller-84d6bc647c-7b8tl   1/1     Running   0          5m13s
verrazzano-cluster-operator-57fb95fc99-kqjll       1/1     Running   0          5m13s
verrazzano-monitoring-operator-7cb5947f4c-x9kfc    1/1     Running   0          5m13s
verrazzano-operator-b6d95b4c4-sxprv                1/1     Running   0          5m13s
vmi-system-api-7c8654dc76-2bdll                    1/1     Running   0          4m44s
vmi-system-es-data-0-6679cf99f4-9p25f              2/2     Running   0          4m44s
vmi-system-es-data-1-8588867569-zlwwx              2/2     Running   0          4m44s
vmi-system-es-ingest-78f6dfddfc-2v5nc              1/1     Running   0          4m44s
vmi-system-es-master-0                             1/1     Running   0          4m44s
vmi-system-es-master-1                             1/1     Running   0          4m44s
vmi-system-es-master-2                             1/1     Running   0          4m44s
vmi-system-grafana-5f7bc8b676-xx49f                1/1     Running   0          4m44s
vmi-system-kibana-649466fcf8-4n8ct                 1/1     Running   0          4m44s
vmi-system-prometheus-0-7f97ff97dc-gfclv           3/3     Running   0          4m44s
vmi-system-prometheus-gw-7cb9df774-48g4b           1/1     Running   0          4m44s
```
