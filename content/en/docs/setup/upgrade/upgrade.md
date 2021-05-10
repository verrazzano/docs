---
title: "Upgrade Guide"
linkTitle: "Upgrade"
description: "How to upgrade Verrazzano"
weight: 7
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
coherence-operator-controller-manager-7557bc4c49-7w55p   1/1     Running   0          27h
fluentd-fzmsl                                            1/1     Running   0          27h
fluentd-r9wwf                                            1/1     Running   0          27h
fluentd-zp2r2                                            1/1     Running   0          27h
oam-kubernetes-runtime-6ff589f66f-r95qv                  1/1     Running   0          27h
verrazzano-api-669c7d7f66-rcnl8                          1/1     Running   0          27h
verrazzano-application-operator-b5b77d676-7w95p          1/1     Running   0          27h
verrazzano-console-6b469dff9c-b2jwk                      1/1     Running   0          27h
verrazzano-monitoring-operator-54cb658774-f6jjm          1/1     Running   0          27h
verrazzano-operator-7f4b99d7d-wg7qm                      1/1     Running   0          27h
vmi-system-es-master-0                                   2/2     Running   0          27h
vmi-system-grafana-74bb7cdf65-k97pb                      2/2     Running   0          27h
vmi-system-kibana-85565975b5-7hfdf                       2/2     Running   0          27h
vmi-system-prometheus-0-7bf464d898-czq8r                 4/4     Running   0          27h
weblogic-operator-7db5cdcf59-qxsr9                       1/1     Running   0          27h
```
