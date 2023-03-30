---
title: "Install With Kubectl"
description: "How to install Verrazzano with kubectl"
weight: 1
draft: false
---

The following instructions show you how to install Verrazzano in a
single Kubernetes cluster using `kubectl`.

## Prerequisites

- Find the Verrazzano prerequisite requirements [here]({{< relref "/docs/setup/prereqs.md" >}}).
- Review the list of the [software versions supported]({{< relref "/docs/setup/prereqs.md#supported-software-versions" >}}) and [installed]({{< relref "/docs/setup/prereqs.md#installed-components" >}}) by Verrazzano.

{{< alert title="NOTE" color="warning" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster.
{{< /alert >}}

## Prepare for the installation

Before installing Verrazzano, see instructions on preparing [Kubernetes platforms]({{< relref "/docs/setup/platforms/" >}}) and installing the [Verrazzano CLI]({{< relref "docs/setup/cli/_index.md" >}}) (optional).
Make sure that you have a valid kubeconfig file pointing to the Kubernetes cluster that you want to use for installing Verrazzano.

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For instructions on how to install a CNI plug-in, see the documentation for your Kubernetes cluster.

You can install Verrazzano using the [Verrazzano CLI]({{< relref "docs/setup/cli/_index.md" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/). See the following respective sections.

## Install the Verrazzano platform operator

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  Using the [Verrazzano]({{< relref "/docs/reference/api/vpo-verrazzano-v1beta1" >}})
custom resource, you can install, uninstall, and upgrade Verrazzano installations.

To install the Verrazzano platform operator:

1. Deploy the Verrazzano platform operator.
{{< clipboard >}}
   ```bash
   $ kubectl apply -f {{<release_asset_operator_url verrazzano-platform-operator.yaml>}}
   ```
{{< /clipboard >}}

2. Wait for the deployment to complete.
{{< clipboard >}}
   ```bash
   $ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator
   ```
   ```
   # Expected response
   deployment "verrazzano-platform-operator" successfully rolled out
   ```
{{< /clipboard >}}

3. Confirm that the operator pod is correctly defined and running.
{{< clipboard >}}
  ```bash
   $ kubectl -n verrazzano-install get pods
   ```
   ```
    # Sample output
    NAME                                            READY   STATUS    RESTARTS   AGE
    verrazzano-platform-operator-59d5c585fd-lwhsx   1/1     Running   0          114s
   ```
{{< /clipboard >}}

## Perform the installation

Verrazzano supports the following installation profiles:  development (`dev`), production (`prod`), and
managed cluster (`managed-cluster`).  For more information, see
[Installation Profiles]({{< relref "/docs/setup/install/profiles.md"  >}}).

This document shows how to create a basic Verrazzano installation using:

* The development (`dev`) installation profile
* Wildcard-DNS, where DNS is provided by [nip.io](https://nip.io) (the default)

**NOTE**: Because the `dev` profile installs self-signed certificates, when installing Verrazzano on macOS, you might see: **Your connection is not private**. For a workaround, see this [FAQ]({{< relref "/docs/faq/_index.md#enable-google-chrome-to-accept-self-signed-verrazzano-certificates" >}}).

For a complete description of Verrazzano configuration options, see the
[Verrazzano Custom Resource Definition]({{< relref "/docs/reference/api/vpo-verrazzano-v1beta1" >}}).

To use other DNS options, see [Customzing DNS]({{< relref "/docs/customize/dns" >}}) for more details.

#### Install Verrazzano

To create a Verrazzano installation as described in the previous section, run the following commands.

{{< clipboard >}}
```bash
$ kubectl apply -f - <<EOF
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: ${VZ_PROFILE:-dev}
EOF
```
{{< /clipboard >}}

{{< clipboard >}}
```bash
$ kubectl wait \
    --timeout=20m \
    --for=condition=InstallComplete verrazzano/example-verrazzano
{{< /clipboard >}}

To use a different profile with the previous example, set the `VZ_PROFILE` environment variable to the name of the profile
you want to install.

If an error occurs, check the log output of the installation. You can view the logs with the following command.

{{< clipboard >}}
```bash
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l app=verrazzano-platform-operator \
    -o jsonpath="{.items[0].metadata.name}") | grep '^{.*}$' \
    | jq -r '."@timestamp" as $timestamp | "\($timestamp) \(.level) \(.message)"'
```
{{< /clipboard >}}

## Verify the installation

Verrazzano installs multiple objects in multiple namespaces. In the `verrazzano-system` namespaces, all the pods in the `Running` state, does not guarantee, but likely indicates that Verrazzano is up and running.
{{< clipboard >}}
To verify the Verrazzano installation, you can use the `vz status` command to determine the status of your installation.  After a successful installation, Verrazzano should be in the `Ready` state.

```bash
$ vz status

# Sample output for a dev profile install
Verrazzano Status
  Name: example-verrazzano
  Namespace: default
  Profile: prod
  Version: v1.5.1
  State: Ready
  Available Components: 23/23
  Access Endpoints:
    consoleUrl: https://verrazzano.default.10.0.0.1.nip.io
    grafanaUrl: https://grafana.vmi.system.default.10.0.0.1.nip.io
    keyCloakUrl: https://keycloak.default.10.0.0.1.nip.io
    kialiUrl: https://kiali.vmi.system.default.10.0.0.1.nip.io
    openSearchDashboardsUrl: https://osd.vmi.system.default.10.0.0.1.nip.io
    openSearchUrl: https://opensearch.vmi.system.default.10.0.0.1.nip.io
    prometheusUrl: https://prometheus.vmi.system.default.10.0.0.1.nip.io
    rancherUrl: https://rancher.default.10.0.0.1.nip.io
```
{{< /clipboard >}}

For installation troubleshooting help, see the [Analysis Advice]({{< relref "/docs/troubleshooting/diagnostictools/analysisadvice/" >}}).

After the installation has completed, you can use the Verrazzano consoles.
For information on how to get the consoles URLs and credentials, see [Access Verrazzano]({{< relref "/docs/access/" >}}).

## Next steps

(Optional) Run the example applications located [here]({{< relref "/docs/samples/_index.md" >}}).
