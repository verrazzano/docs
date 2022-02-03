---
title: "Install Guide"
description: "How to install Verrazzano"
weight: 1
draft: false
---

The following instructions show you how to install Verrazzano in a
single Kubernetes cluster.

## Prerequisites

- Find the Verrazzano prerequisite requirements [here]({{< relref "/docs/setup/prereqs.md" >}}).
- Review the list of the [software versions supported]({{< relref "/docs/setup/prereqs.md#supported-software-versions" >}}) and [installed]({{< relref "/docs/setup/prereqs.md#installed-components" >}}) by Verrazzano.


## Prepare for the install

Before installing Verrazzano, see instructions on preparing [Kubernetes platforms]({{< relref "/docs/setup/platforms/" >}}).

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For instructions on how to install a CNI plug-in, see the documentation for your Kubernetes cluster.

## Install the Verrazzano platform operator

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  Using the [Verrazzano]({{< relref "/docs/reference/api/verrazzano/verrazzano.md" >}})
custom resource, you can install, uninstall, and upgrade Verrazzano installations.

To install the Verrazzano platform operator:

1. Deploy the Verrazzano platform operator.

    ```shell
    $ kubectl apply -f {{<release_asset_url operator.yaml>}}
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

## Perform the install

Verrazzano supports the following installation profiles:  development (`dev`), production (`prod`), and
managed cluster (`managed-cluster`).  For more information on profiles, see
[Installation Profiles]({{< relref "/docs/setup/install/profiles.md"  >}}).

This page shows how to create a basic Verrazzano installation using:

* The development (`dev`) installation profile
* Wildcard-DNS, where DNS is provided by [nip.io](https://nip.io) (the default)

{{< alert title="NOTE" color="warning" >}}Because the `dev` profile installs self-signed certificates, when installing Verrazzano on macOS, you might see: **Your connection is not private**. For a workaround, see this [FAQ]({{< relref "/docs/faq/FAQ#enable-google-chrome-to-accept-self-signed-verrazzano-certificates" >}}).
{{< /alert >}}

For a complete description of Verrazzano configuration options, see the
[Verrazzano Custom Resource Definition]({{< relref "/docs/reference/api/verrazzano/verrazzano.md" >}}).

To use other DNS options, see the [Customzing DNS](/docs/setup/install/customizing/dns/) page for more details.

#### Install Verrazzano

To create a Verrazzano installation as described in the previous section, run the following commands:

```shell
$ kubectl apply -f - <<EOF
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: ${VZ_PROFILE:-dev}
EOF
$ kubectl wait \
    --timeout=20m \
    --for=condition=InstallComplete verrazzano/example-verrazzano
```

To use a different profile with the above example, set the `VZ_PROFILE` environment variable to the name of the profile
you want to install.

To monitor the Console log output of the installation:
```shell
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l job-name=verrazzano-install-example-verrazzano \
    -o jsonpath="{.items[0].metadata.name}")
```

## Verify the install

Verrazzano installs multiple objects in multiple namespaces. In the `verrazzano-system` namespaces, all the pods in the `Running` state, does not guarantee, but likely indicates that Verrazzano is up and running.
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

## (Optional) Run the example applications
Example applications are located [here]({{< relref "/docs/samples/_index.md" >}}).

##### To get the consoles URLs and credentials, see [Access Verrazzano]({{< relref "/docs/operations/_index.md" >}}).
