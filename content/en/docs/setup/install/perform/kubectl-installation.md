---
title: "Install With kubectl"
description: "Install Verrazzano using `kubectl`"
weight: 1
draft: false
aliases:
- "/docs/setup/install/kubectl-installation"
---

The following instructions show you how to install Verrazzano in a
single Kubernetes cluster using `kubectl`.

## Prerequisites

- Find the Verrazzano prerequisite requirements [here]({{< relref "/docs/setup/install/prepare/prereqs.md" >}}).
- Review the list of the [software versions supported]({{< relref "/docs/setup/install/prepare/prereqs.md#supported-software-versions" >}}) and [installed]({{< relref "/docs/setup/install/prepare/prereqs.md#installed-components" >}}) by Verrazzano.

{{< alert title="NOTE" color="primary" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster.
{{< /alert >}}

## Prepare for the installation

Before installing Verrazzano, see instructions on preparing [Kubernetes platforms]({{< relref "/docs/setup/install/prepare/platforms/" >}}) and installing the [Verrazzano CLI]({{< relref "docs/setup/install/prepare/cli-setup.md" >}}) (optional).
Make sure that you have a valid kubeconfig file pointing to the Kubernetes cluster that you want to use for installing Verrazzano.

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For instructions on how to install a CNI plug-in, see the documentation for your Kubernetes cluster.

You can install Verrazzano using the [Verrazzano CLI]({{< relref "docs/setup/install/prepare/cli-setup.md" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/). See the following respective sections.

## Install the Verrazzano platform operator

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  Using the [Verrazzano]({{< relref "/docs/reference/vpo-verrazzano-v1beta1" >}})
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
[Installation Profiles]({{< relref "/docs/setup/install/perform/profiles.md"  >}}).

This document shows how to create a basic Verrazzano installation using:

* The development (`dev`) installation profile
* Wildcard-DNS, where DNS is provided by [nip.io](https://nip.io) (the default)

**NOTE**: Because the `dev` profile installs self-signed certificates, when installing Verrazzano on macOS, you might see: **Your connection is not private**. For a workaround, see this [FAQ]({{< relref "/docs/troubleshooting/faq.md#enable-google-chrome-to-accept-self-signed-verrazzano-certificates" >}}).

For a complete description of Verrazzano configuration options, see the
[Verrazzano Custom Resource Definition]({{< relref "/docs/reference/vpo-verrazzano-v1beta1" >}}).

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

## Next steps

Verify the installed Verrazzano using `kubectl`. See [Verify using CLI]({{< relref "/docs/setup/install/verify/kubectl-verify.md" >}}).
