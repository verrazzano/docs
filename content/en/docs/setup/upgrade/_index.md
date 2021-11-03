---
title: "Upgrade"
linkTitle: "Upgrade"
description: "How to upgrade Verrazzano"
weight: 5
draft: false
---

A Verrazzano installation consists of a stack of components, such as cert-manager, where each component has a
specific release version that may be different from the overall Verrazzano version.  The Verrazzano platform operator
knows the versions of each component associated with the Verrazzano version.  When you perform the initial Verrazzano
installation, the appropriate version of each component is installed by the platform operator.
Post installation, it may be necessary to update one or more of the component images or Helm charts.  This update is also
handled by the platform operator and is called an `upgrade`.  Currently, Verrazzano does only patch-level upgrades,
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

## Upgrade the Verrazzano platform operator

In order to upgrade an existing Verrazzano installation, you must first upgrade the [Verrazzano platform operator](https://github.com/verrazzano/verrazzano-platform-operator).

1. Upgrade the Verrazzano platform operator.

   **NOTE:** If you are using a private container registry, then to update the platform operator, follow the instructions at [Use a Private Registry]({{< relref "/docs/setup/private-registry/private-registry.md" >}}).

   To upgrade to the latest version:

   ```shell
   $ kubectl apply -f {{<release_asset_url operator.yaml>}}
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

## Upgrade Verrazzano

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
   $ kubectl wait \
       --timeout=10m \
       --for=condition=UpgradeComplete verrazzano/my-verrazzano
   ```

## Verify the upgrade

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

## Upgrade applications in the Istio service mesh
If your upgrade includes a minor version change to Istio, you must complete these additional actions to ensure that applications managed in the Istio mesh get upgraded properly.
Before making any alterations to the application components, ensure that the Verrazzano Custom Resource status is `UpgradeComplete` and that all pods in the `verrazzano-system` namespace are in the `Running` state.

If you are upgrading Verrazzano from version `1.0.X` to version `1.1.X`, then you are required to restart the application.

### Restarting applications
If your application namespace has the `istio-injection=enabled` label, then your application components are in the Istio service mesh.
As such, your application must be restarted to upgrade the Istio proxy sidecars to the new version.
For WebLogic applications, the WebLogic domain will undergo a hard restart. This will result in WebLogic application downtime as the domains get restarted.

To trigger this restart, you can annotate the application configuration with the key `verrazzano.io/restart-version`.
When the annotation is added or the value is modified, Verrazzano will initiate a restart of all the application components.
Although the value of the annotation is insignificant to the upgrade, we recommend that you use whole number values to help keep track of your upgrades.
For example, you can annotate the Bob's Books example application by using the following command:

```shell
$ kubectl annotate appconfig bobs-books -n bobs-books verrazzano.io/restart-version="3" --overwrite
```

To verify that this example application configuration has been updated, this command will return the value of your annotation:

```shell
$ kubectl get appconfig bobs-books -n bobs-books -o jsonpath="{.metadata.annotations.verrazzano\.io/restart-version}"
```

After completing the annotations and restarting, verify that your application is up and running as expected.
