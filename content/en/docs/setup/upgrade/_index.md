---
title: "Upgrade"
linkTitle: "Upgrade"
description: "How to upgrade Verrazzano"
weight: 6
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

## Application and system pod restarts
Upgrading Verrazzano 1.0.x to 1.1.0 will result in an upgrade of Istio from 1.7.3 to 1.10.4.  Because of this, all the pods
in the Istio mesh need to be restarted so that the new Envoy proxy sidecar can be injected into the pods.  This includes both Verrazzano
applications, along with Verrazzano system pods, such as the NGINX Ingress Controller.  For WebLogic workloads, Verrazzano will shut down
every domain, do the upgrade, then start every domain.  For all other workloads, Verrazzano will perform a rolling restart
when the upgrade is complete.  There is no user involvement related to restarting applications; it is done automatically during upgrade.

## Upgrade steps
It is important to distinguish between updating the Verrazzano platform operator versus upgrading the Verrazzano installation.
The platform operator contains the newer component charts and image versions, so it must be updated prior to upgrading the installation.
Updating the platform operator has no effect on an existing installation until you initiate the Verrazzano installation upgrade.
Currently, there is no way to roll back either the platform operator update or the Verrazzano installation upgrade.  

Upgrading an existing Verrazzano installation is a two-step process:

* Upgrade the Verrazzano platform operator to the [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/) to which you want to upgrade.
* Update the Verrazzano installation.  

### Upgrade the Verrazzano platform operator
In order to upgrade an existing Verrazzano installation, you must first upgrade the [Verrazzano platform operator](https://github.com/verrazzano/verrazzano).

1. Upgrade the Verrazzano platform operator.

   **NOTE:** If you are using a private container registry, then to update the platform operator, follow the instructions at [Use a Private Registry]({{< relref "/docs/setup/private-registry/private-registry.md" >}}).

   To upgrade to the latest version:

   ```
   $ kubectl apply -f {{<release_asset_url operator.yaml>}}
   ```

   To upgrade to a specific version, where `<version>` is the desired version:

   ```
   $ kubectl apply -f https://github.com/verrazzano/verrazzano/releases/download/<version>/operator.yaml
   ```


1. Wait for the deployment to complete.

   ```
   $ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator

   # Expected response
   deployment "verrazzano-platform-operator" successfully rolled out
   ```

1. Confirm that the operator pod is correctly defined and running.

   ```
   $ kubectl -n verrazzano-install get pods

   # Sample output
   NAME                                            READY   STATUS    RESTARTS   AGE
   verrazzano-platform-operator-59d5c585fd-lwhsx   1/1     Running   0          114s
   ```

### Upgrade Verrazzano

To upgrade the Verrazzano installation, you need to change the version of your installed Verrazzano resource to the version supported by the
Verrazzano Platform Operator.

**NOTE:** You may only change the version field during an upgrade; changes to other fields or component configurations are not supported at this time.

1. Update the `Verrazzano` resource to the desired version.

      To upgrade the Verrazzano components, you must update the `version` field in your `Verrazzano` resource spec to
      match the version supported by the platform operator to which you upgraded and apply it to the cluster.

      The value of the `version` field in the resource spec must be a [Semantic Versioning](https://semver.org/) value
      corresponding to a valid [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/).

      You can update the resource by doing one of the following:

      a. Editing the YAML file you used to install Verrazzano and setting the version field to the latest version.

      For example, to upgrade to `{{<release_version>}}`, your YAML file should be edited to add or update the version field:

      ```yaml
      apiVersion: install.verrazzano.io/v1alpha1
      kind: Verrazzano
      metadata:
        name: example-verrazzano
      spec:
        profile: dev
        version: {{<release_version>}}
      ```

      Then apply the resource to the cluster (if you have not edited the resource in-place using `kubectl edit`):

      ```
      $ kubectl apply -f example-verrazzano.yaml
      ```

      b. Editing the `Verrazzano` resource directly using `kubectl` and setting the version field directly, for example:

      ```
      $ kubectl edit verrazzano example-verrazzano
      # In the resource editor, add or update the version field to "version: {{<release_version>}}", then save.
      ```

1. Wait for the upgrade to complete:

   ```
   $ kubectl wait \
       --timeout=10m \
       --for=condition=UpgradeComplete verrazzano/example-verrazzano
   ```

## Verify the upgrade

Check that all the pods in the `verrazzano-system` namespace are in the `Running` state.  While the upgrade is in progress,
you may see some pods terminating and restarting as newer versions of components are applied, for example:
```
$ kubectl get pods -n verrazzano-system

# Sample output
coherence-operator-866798c99d-r69xt                1/1     Running   1          43m
fluentd-f9fbv                                      2/2     Running   0          38m
fluentd-n79c4                                      2/2     Running   0          38m
fluentd-xslzw                                      2/2     Running   0          38m
oam-kubernetes-runtime-56cdb56c98-wn2mb            1/1     Running   0          43m
verrazzano-application-operator-7c95ddd5b5-7xzmn   1/1     Running   0          42m
verrazzano-authproxy-594d8c8dcd-llmlr              2/2     Running   0          38m
verrazzano-console-74dbf97fdf-zxvvn                2/2     Running   0          38m
verrazzano-monitoring-operator-6fcf8484fd-gfkhs    1/1     Running   0          38m
verrazzano-operator-66c8566f95-8lbs6               1/1     Running   0          38m
vmi-system-es-master-0                             2/2     Running   0          38m
vmi-system-grafana-799d79648d-wsdp4                2/2     Running   0          38m
vmi-system-kiali-574c6dd94d-f49jv                  2/2     Running   0          41m
vmi-system-kibana-77f8d998f4-zzvqr                 2/2     Running   0          38m
vmi-system-prometheus-0-7f89d54fbf-brg6x           3/3     Running   0          36m
weblogic-operator-7b447fdb47-wlw64                 2/2     Running   0          42m
```

Check that the pods in your application namespaces are ready, for example:
```
$ kubectl get pods -n todo-list

# Sample output
NAME                     READY   STATUS    RESTARTS   AGE
mysql-67575d8954-d4vkm   2/2     Running   0          39h
tododomain-adminserver   4/4     Running   0          39h
```
