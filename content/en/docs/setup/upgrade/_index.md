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
If Verrazzano has a new version of Istio, then all the pods with Istio proxy sidecars
need to be restarted.  This is done so that the new version of the proxy sidecar can be injected into the pods.
All Verrazzano pods containing Istio proxy sidecars will be restarted.  This includes Verrazzano system pods,
such as the NGINX Ingress Controller, along with Verrazzano applications.  For WebLogic workloads, Verrazzano
will shut down every domain, do the upgrade, then start every domain.  For all other workloads, Verrazzano will perform a rolling restart
when the upgrade is complete.  There is no user involvement related to restarting applications; it is done automatically during upgrade.

## Upgrade steps
It is important to distinguish between updating the Verrazzano platform operator versus upgrading the Verrazzano installation.
The platform operator contains the newer component charts and image versions, so it must be updated prior to upgrading the installation.
Updating the platform operator has no effect on an existing installation until you initiate the Verrazzano installation upgrade.
Currently, there is no way to roll back either the platform operator update or the Verrazzano installation upgrade.  

You can upgrade Verrazzano using the  [Verrazzano CLI]({{< relref "/docs/setup/install/installation.md" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/).
See the following respective sections.

{{< tabs tabTotal="2" >}}
{{< tab tabName="vz" >}}
<br>

## Upgrade Verrazzano

In one simple step, you can upgrade to a specified version of Verrazzano using this command:

1. Update the `Verrazzano` resource to the desired version.

   To update to the latest version (default):

   ```
   $ vz upgrade
   ```

   To update to a specific version, where `<version>` is the desired version:

   ```
   $ vz upgrade --version <version>
   ```

2. Wait for the upgrade to complete.
   Upgrade logs will be streamed to the command window until the upgrade has completed
   or until the default timeout (30m) has been reached.

{{< /tab >}}
{{< tab tabName="kubectl" >}}
<br>

Upgrading an existing Verrazzano installation is a two-step process:

* Update the Verrazzano platform operator to the [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/) to which you want to upgrade.
* Upgrade the Verrazzano installation.  

### Update the Verrazzano platform operator
In order to upgrade an existing Verrazzano installation, you must first update the [Verrazzano platform operator](https://github.com/verrazzano/verrazzano).

1. Update the Verrazzano platform operator.

   **NOTE:** If you are using a private container registry, then to update the platform operator, follow the instructions at [Use a Private Registry]({{< relref "/docs/setup/private-registry/private-registry.md" >}}).

   To update to the latest version:

   ```
   $ kubectl apply -f {{<release_asset_url operator.yaml>}}
   ```

   To update to a specific version, where `<version>` is the desired version:

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
Verrazzano platform operator.

**NOTE:** You may only change the `version` field during an upgrade; changes to other fields or component configurations are not supported at this time.

In one simple step, you can upgrade to a specified version of Verrazzano using this command:

   ```
   $ kubectl patch vz example-verrazzano -p '{"spec":{"version":"{{<release_version>}}"}}' --type=merge
   ```
Alternatively, you can upgrade the Verrazzano installation using the following steps:
1. Update the `Verrazzano` resource to the desired version.

      To upgrade the Verrazzano components, you must update the `version` field in your `Verrazzano` resource spec to
      match the version supported by the platform operator to which you upgraded and apply it to the cluster.

      The value of the `version` field in the resource spec must be a [Semantic Versioning](https://semver.org/) value
      corresponding to a valid [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/).

      To update the resource, do one of the following:

      a. Edit the YAML file you used to install Verrazzano and set the `version` field to the latest version.

      For example, to upgrade to `{{<release_version>}}`, your YAML file should be edited to add or update the `version` field.

      ```yaml
      apiVersion: install.verrazzano.io/v1alpha1
      kind: Verrazzano
      metadata:
        name: example-verrazzano
      spec:
        profile: dev
        version: {{<release_version>}}
      ```

      Then, apply the resource to the cluster (if you have not edited the resource in-place using `kubectl edit`).

      ```
      $ kubectl apply -f example-verrazzano.yaml
      ```

      b. Edit the `Verrazzano` resource directly using `kubectl` and set the `version` field directly, for example:

      ```
      $ kubectl edit verrazzano example-verrazzano
      # In the resource editor, add or update the version field to "version: {{<release_version>}}", then save.
      ```

1. Wait for the upgrade to complete.

   ```
   $ kubectl wait \
       --timeout=10m \
       --for=condition=UpgradeComplete verrazzano/example-verrazzano
   ```
{{< /tab >}}
{{< /tabs >}}
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

## Upgrade failures

In Verrazzano 1.3 and later, upgrade will continue to run until it succeeds or until you delete the Verrazzano CR.  In previous versions,
upgrade could fail and transition to the `UpgradeFailed` state.  If that happens, and you updated the Verrazzano platform operator to 1.3+,
then the Verrazzano CR will transition to `UpgradePaused`.  To continue with the upgrade, you must change the CR version to the current
version of the Verrazzano platform operator.  The following steps illustrate this scenario:

1. You install Verrazzano 1.1.2.
2. You upgrade to 1.2.0 by changing the Verrazzano CR version field to v1.2.0.
   - For some reason, the upgrade failed and the Verrazzano CR state transitions to `UpgradeFailed`.
3. You update the Verrazzano platform operator to 1.3.0.
   - The Verrazzano CR state transitions to `UpgradePaused`.
4. You change the Verrazzano CR version field to v1.3.0.
   - The Verrazzano CR state transitions to `Upgrading` and stays in that state until it completes, then it transitions to `UpgradeComplete`.  


To see detailed progress of the upgrade, view the logs with the following command:

```
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l app=verrazzano-platform-operator \
    -o jsonpath="{.items[0].metadata.name}") | grep '^{.*}$' \
    | jq -r '."@timestamp" as $timestamp | "\($timestamp) \(.level) \(.message)"'
```
