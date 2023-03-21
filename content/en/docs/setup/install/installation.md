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

{{< alert title="NOTE" color="warning" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster.
{{< /alert >}}

## Prepare for the installation

Before installing Verrazzano, see instructions on preparing [Kubernetes platforms]({{< relref "/docs/setup/platforms/" >}}) and installing the [Verrazzano CLI]({{< relref "docs/setup/cli/_index.md" >}}) (optional).
Make sure that you have a valid kubeconfig file pointing to the Kubernetes cluster that you want to use for installing Verrazzano.

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For instructions on how to install a CNI plug-in, see the documentation for your Kubernetes cluster.

You can install Verrazzano using the [Verrazzano CLI]({{< relref "docs/setup/cli/_index.md" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/). See the following respective sections.

{{< tabs tabTotal="2" >}}
{{< tab tabName="vz" >}}
<br>

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  Using the [Verrazzano]({{< relref "/docs/reference/api/vpo-verrazzano-v1beta1" >}})
custom resource, you can install, uninstall, and upgrade Verrazzano installations. When applying the Verrazzano custom resource, the Verrazzano CLI deploys and installs the Verrazzano platform operator; you need only to install Verrazzano as described in the following section.

## Perform the installation

Verrazzano supports the following installation profiles:  development (`dev`), production (`prod`), and
managed cluster (`managed-cluster`).  For more information, see
[Installation Profiles]({{< relref "/docs/setup/install/profiles.md"  >}}).

This document shows how to create a basic Verrazzano installation using:

* The development (`dev`) installation profile
* Wildcard-DNS, where DNS is provided by [nip.io](https://nip.io) (the default)

**NOTE**: Because the `dev` profile installs self-signed certificates, when installing Verrazzano on macOS, you might see: **Your connection is not private**. For a workaround, see this [FAQ]({{< relref "/docs/faq/_index.md#enable-google-chrome-to-accept-self-signed-verrazzano-certificates" >}}).

For an overview of how to configure Verrazzano, see [Modify Verrazzano Installations]({{< relref "/docs/setup/install/modify-installation.md" >}}).
For a complete description of Verrazzano configuration options, see the
[Verrazzano Custom Resource Definition]({{< relref "/docs/reference/api/vpo-verrazzano-v1beta1" >}}).

To use other DNS options, see [Customizing DNS]({{< relref "/docs/customize/dns" >}}) for more details.

#### Install Verrazzano

To create a Verrazzano installation as described in the previous section, run the following commands.

1. Install Verrazzano with its `dev` profile.
{{< clipboard >}}
<div class="highlight">


    $ vz install -f - <<EOF
    apiVersion: install.verrazzano.io/v1beta1
    kind: Verrazzano
    metadata:
      name: example-verrazzano
    spec:
      profile: dev
      defaultVolumeSource:
        persistentVolumeClaim:
          claimName: verrazzano-storage
      volumeClaimSpecTemplates:
        - metadata:
            name: verrazzano-storage
          spec:
            resources:
              requests:
                storage: 2Gi
    EOF

</div>
{{< /clipboard >}}


   This command installs the Verrazzano platform operator and applies the Verrazzano custom resource.

2. Wait for the installation to complete.
   Installation logs will be streamed to the command window until the installation has completed
   or until the default timeout (30m) has been reached.

To use a different profile with the previous example, set the `VZ_PROFILE` environment variable to the name of the profile you want to install.

{{< /tab >}}
{{< tab tabName="kubectl" >}}
<br>

## Install the Verrazzano platform operator

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  Using the [Verrazzano]({{< relref "/docs/reference/api/vpo-verrazzano-v1beta1" >}})
custom resource, you can install, uninstall, and upgrade Verrazzano installations.

To install the Verrazzano platform operator:

1. Deploy the Verrazzano platform operator.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl apply -f {{<release_asset_operator_url verrazzano-platform-operator.yaml>}}
   ```
</div>
{{< /clipboard >}}

2. Wait for the deployment to complete.

{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator
   ```
   ```
   # Expected response
   deployment "verrazzano-platform-operator" successfully rolled out
   ```
</div>
{{< /clipboard >}}

3. Confirm that the operator pod is correctly defined and running.
{{< clipboard >}}
<div class="highlight">

  ```
   $ kubectl -n verrazzano-install get pods
   ```
   ```
    # Sample output
    NAME                                            READY   STATUS    RESTARTS   AGE
    verrazzano-platform-operator-59d5c585fd-lwhsx   1/1     Running   0          114s
   ```
</div>
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
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: ${VZ_PROFILE:-dev}
EOF
```

</div>
{{< /clipboard >}}

{{< clipboard >}}
<div class="highlight">

```
$ kubectl wait \
    --timeout=20m \
    --for=condition=InstallComplete verrazzano/example-verrazzano
```
</div>
{{< /clipboard >}}

To use a different profile with the previous example, set the `VZ_PROFILE` environment variable to the name of the profile
you want to install.

If an error occurs, check the log output of the installation. You can view the logs with the following command.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l app=verrazzano-platform-operator \
    -o jsonpath="{.items[0].metadata.name}") | grep '^{.*}$' \
    | jq -r '."@timestamp" as $timestamp | "\($timestamp) \(.level) \(.message)"'
```
</div>
{{< /clipboard >}}

{{< /tab >}}
{{< /tabs >}}


## Verify the installation

Verrazzano installs multiple objects in multiple namespaces. In the `verrazzano-system` namespaces, all the pods in the `Running` state, does not guarantee, but likely indicates that Verrazzano is up and running.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get pods -n verrazzano-system

# Sample output for a dev profile install
NAME                                                       READY   STATUS    RESTARTS   AGE
coherence-operator-d5565cd5d-dkm95                         1/1     Running   0          9m49s
fluentd-sgtcg                                              2/2     Running   0          2m46s
oam-kubernetes-runtime-665ff44c8-ldbqv                     1/1     Running   0          11m
verrazzano-application-operator-9f87f7897-25crr            1/1     Running   0          9m37s
verrazzano-application-operator-webhook-5bd7ccbb45-wp874   1/1     Running   0          9m37s
verrazzano-authproxy-66767cdfc5-lsc22                      3/3     Running   0          8m31s
verrazzano-cluster-operator-994fb6c7d-29pd7                1/1     Running   0          9m41s
verrazzano-cluster-operator-webhook-85b85f89f4-25jgj       1/1     Running   0          9m41s
verrazzano-console-7d999bf7-6nncm                          2/2     Running   0          8m9s
verrazzano-monitoring-operator-754c897d65-jfmb9            2/2     Running   0          8m35s
vmi-system-es-master-0                                     2/2     Running   0          7m59s
vmi-system-grafana-6966f9965d-cm5pz                        3/3     Running   0          7m58s
vmi-system-kiali-5bcfb7f775-9cc5h                          2/2     Running   0          8m28s
vmi-system-osd-6c974854df-klgpv                            2/2     Running   0          6m2s
weblogic-operator-c4f766c7c-knmpx                          2/2     Running   0          9m33s
weblogic-operator-webhook-547b9756f4-454rq                 1/1     Running   0          9m33s
```
</div>
{{< /clipboard >}}

For installation troubleshooting help, see [Analysis Advice]({{< relref "/docs/troubleshooting/diagnostictools/analysisadvice/" >}}).

After the installation has completed, you can use the Verrazzano consoles.
For information on how to get the consoles URLs and credentials, see [Access Verrazzano]({{< relref "/docs/access/" >}}).

## Next steps

(Optional) Run the example applications located [here]({{< relref "/docs/samples/_index.md" >}}).
