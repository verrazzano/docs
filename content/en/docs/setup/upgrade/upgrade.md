---
title: "Upgrade"
linkTitle: "Upgrade"
description: "How to upgrade Verrazzano"
weight: 3
draft: false
---

A Verrazzano installation consists of a stack of components, such as cert-manager, where each component has a
specific release version that may be different from the overall Verrazzano version.  The Verrazzano platform operator
knows the versions of each component associated with the Verrazzano version.  When you perform the initial Verrazzano
installation, the appropriate version of each component is installed by the platform operator.
Post installation, it may be necessary to update one or more of the component images or Helm charts.  This update is also
handled by the platform operator and is called an `upgrade`.  Currently, Verrazzano does only patch-level upgrade,
where a `helm upgrade` command can be issued for the component.  Typically, patch-level upgrades simply replace component
images with newer versions.

It is important to distinguish between updating the Verrazzano platform operator versus upgrading the Verrazzano installation.
The platform operator contains the newer component charts and image versions, so it must be updated prior to upgrading the installation.
Updating the platform operator has no effect on an existing installation until you initiate the Verrazzano installation upgrade.
Currently, there is no way to roll back either the platform operator update or the Verrazzano installation upgrade.  Upgrading
will not have any impact on running applications.

Upgrading an existing Verrazzano installation involves:

* Upgrading the Verrazzano platform operator to the [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/) to which you want to upgrade.
* Updating the version of your installed `Verrazzano` resource to the version supported by the upgraded operator.

**NOTE:** You may only change the version field during an upgrade; changes to other fields or component configurations are not supported at this time.

### Upgrade the Verrazzano platform operator

In order to upgrade an existing Verrazzano installation, you must first upgrade the [Verrazzano platform operator](https://github.com/verrazzano/verrazzano-platform-operator).

1. Upgrade the Verrazzano platform operator.

   **NOTE:** If you are using a private container registry, follow the instructions at [Using a Private Registry](../../private-registry/private-registry) to update the platform operator.

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

      For example, to upgrade to `v0.17.0`, your YAML file should be edited to add or update the version field:

      ```yaml
      apiVersion: install.verrazzano.io/v1alpha1
      kind: Verrazzano
      metadata:
        name: my-verrazzano
      spec:
        profile: dev
        version: v0.17.0
      ```

      Then apply the resource to the cluster (if you have not edited the resource in-place using `kubectl edit`):

      ```shell
      $ kubectl apply -f my-verrazzano.yaml
      ```

      b. Editing the `Verrazzano` resource directly using `kubectl` and setting the version field directly, for example:

      ```shell
      $ kubectl edit verrazzano my-verrazzano
      # In the resource editor, add or update the version field to "version: v0.17.0", then save.
      ```

1. Wait for the upgrade to complete:

   ```shell
   $ kubectl wait --timeout=10m --for=condition=UpgradeComplete verrazzano/my-verrazzano
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
