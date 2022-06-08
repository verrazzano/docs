previous---
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

    ```
    $ kubectl apply -f {{<release_asset_url operator.yaml>}}
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

To use other DNS options, see the [Customzing DNS](/docs/setup/customizing/dns/) page for more details.

#### Install Verrazzano

To create a Verrazzano installation as described in the previous section, run the following commands:

```
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

To use a different profile with the previous example, set the `VZ_PROFILE` environment variable to the name of the profile
you want to install.

If an error occurs, check the log output of the installation. You can view the logs with the following command:

```
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l app=verrazzano-platform-operator \
    -o jsonpath="{.items[0].metadata.name}") | grep '^{.*}$' \
    | jq -r '."@timestamp" as $timestamp | "\($timestamp) \(.level) \(.message)"'
```


For more help troubleshooting the installation, see [Analysis Advice]({{< relref "/docs/troubleshooting/diagnostictools/analysisadvice/" >}}).

After the installation is complete, you can use the console URLs.
For more information on how to access the Verrazzano consoles, see [Access Verrazzano]({{< relref "/docs/access/" >}}).
## Verify the install

Verrazzano installs multiple objects in multiple namespaces. In the `verrazzano-system` namespaces, all the pods in the `Running` state, does not guarantee, but likely indicates that Verrazzano is up and running.
```
$ kubectl get pods -n verrazzano-system

# Sample output
coherence-operator-dcfb446df-24djp                 1/1     Running   1          49m
fluentd-h65xf                                      2/2     Running   1          45m
oam-kubernetes-runtime-6645df49cd-6q96c            1/1     Running   0          49m
verrazzano-application-operator-85ffd7f77b-rhwk7   1/1     Running   0          48m
verrazzano-authproxy-58db5b9484-nhnql              2/2     Running   0          45m
verrazzano-console-5dbdc579bd-hm4rh                2/2     Running   0          45m
verrazzano-monitoring-operator-599654889d-lbb4z    1/1     Running   0          45m
verrazzano-operator-7b6fd64dd5-8j9h8               1/1     Running   0          45m
vmi-system-es-master-0                             2/2     Running   0          45m
vmi-system-grafana-5558d65b46-pxg78                2/2     Running   0          45m
vmi-system-kiali-5949966fb8-465s8                  2/2     Running   0          48m
vmi-system-kibana-86b894d8f6-q4vb5                 2/2     Running   0          45m
vmi-system-prometheus-0-859fcd87dc-m5ws9           3/3     Running   0          44m
weblogic-operator-646756c75c-hgz6j                 2/2     Running   0          49m
```

## (Optional) Run the example applications
Example applications are located [here]({{< relref "/docs/samples/_index.md" >}}).

##### To get the consoles URLs and credentials, see [Access Verrazzano]({{< relref "/docs/access/_index.md" >}}).
