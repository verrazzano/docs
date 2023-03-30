---
title: "Quick Start"
description: "Instructions for getting started with Verrazzano"
weight: 2
---


## Prerequisites

The Quick Start assumes that you have already installed a
[Kubernetes](https://kubernetes.io/) cluster. For instructions on preparing Kubernetes
platforms for installing Verrazzano, see [Platform Setup]({{< relref "/docs/setup/platforms/_index.md" >}}).

- Find the Verrazzano prerequisite requirements [here]({{< relref "/docs/setup/prereqs.md" >}}).
- Install  the [Verrazzano CLI]({{< relref "docs/setup/cli/_index.md" >}}).

**NOTE**: If you just created the cluster, then you must wait until your nodes reach `Ready` status before installing Verrazzano.

For detailed Verrazzano installation instructions, see the [Installation Guide]({{< relref "/docs/setup/install" >}}).

## Install Verrazzano

Verrazzano provides a Kubernetes [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  The operator works with a
[custom resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) defined in the cluster.
You can install, uninstall, and update Verrazzano installations by updating the
[Verrazzano custom resource]({{< relref "/docs/reference/api/vpo-verrazzano-v1beta1" >}}).
The [Verrazzano platform operator](https://github.com/verrazzano/verrazzano) controller will apply the configuration from the custom resource to the cluster for you.

You install Verrazzano by creating a Verrazzano custom resource in
your Kubernetes cluster.  Verrazzano currently supports a default production (`prod`)
profile and a development (`dev`) profile suitable for evaluation. For more information, see [Installation Profiles]({{< relref "/docs/setup/install/profiles.md" >}}).

Using the Quick Start, you'll install the `dev` profile.

{{< alert title="NOTE" color="warning" >}}Because the `dev` profile installs self-signed certificates, when installing Verrazzano on macOS, you might see: **Your connection is not private**. For a workaround, see this [FAQ]({{< relref "/docs/faq/_index.md#enable-google-chrome-to-accept-self-signed-verrazzano-certificates" >}}).
{{< /alert >}}

### Install Verrazzano using the Verrazzano CLI

For information about installing the Verrazzano CLI, see [CLI Setup]({{< relref "docs/setup/cli/_index.md" >}}).

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

2. Wait for the installation to complete.
   Installation logs will be streamed to the command window until the installation has completed
   or until the default timeout (30m) has been reached.

**NOTE**: For some applications, the Kiali console may show warnings for objects that replicate hostname/port configurations across multiple IngressTraits. These warnings do not impact functionality and can be suppressed with the following [component override]({{< relref "docs/guides/app-deployment/application-deployment-guide.md#suppress-kiali-console-warnings" >}}).

## Deploy an example application

The [Hello World Helidon]({{< relref "/docs/samples/hello-helidon/_index.md" >}})
example application provides a simple *Hello World* REST service written with [Helidon](https://helidon.io).
For more information and the code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).

To deploy the Hello World Helidon example application:



1. Create a namespace for the example application and add labels identifying the namespace as managed by Verrazzano and
   enabled for Istio.
{{< clipboard >}}
<div class="highlight">

    $ kubectl create namespace hello-helidon
    $ kubectl label namespace hello-helidon verrazzano-managed=true istio-injection=enabled

</div>
{{< /clipboard >}}


1. Apply the `hello-helidon` resources to deploy the application.
{{< clipboard >}}
<div class="highlight">

    $ kubectl apply -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-comp.yaml >}} -n hello-helidon
    $ kubectl apply -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-app.yaml >}} -n hello-helidon

</div>
{{< /clipboard >}}

1. Wait for the application to be ready.
{{< clipboard >}}
<div class="highlight">

    $ kubectl wait \
        --for=condition=Ready pods \
        --all -n hello-helidon \
        --timeout=300s

    # Sample output
    pod/hello-helidon-deployment-78468f5f9c-czmp4 condition met

</div>
{{< /clipboard >}}

   This creates the Verrazzano OAM Component application resources for the example and waits for the pods in the `hello-helidon`
   namespace to be ready.

1.  Save the host name of the load balancer exposing the application's REST service endpoints.
{{< clipboard >}}
<div class="highlight">

    $ HOST=$(kubectl get gateways.networking.istio.io hello-helidon-hello-helidon-gw \
        -n hello-helidon \
        -o jsonpath='{.spec.servers[0].hosts[0]}')

</div>
{{< /clipboard >}}

1.  Get the default message.
{{< clipboard >}}
<div class="highlight">

    $ curl -sk \
        -X GET \
        "https://${HOST}/greet"

    # Expected response
    {"message":"Hello World!"}

</div>
{{< /clipboard >}}


## Uninstall the example application

1. Delete the Verrazzano application resources.
{{< clipboard >}}
<div class="highlight">

    $ kubectl delete -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-comp.yaml >}}
    $ kubectl delete -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-app.yaml >}}

</div>
{{< /clipboard >}}

1. Delete the example namespace.
{{< clipboard >}}
<div class="highlight">

    $ kubectl delete namespace hello-helidon

    # Expected response
    namespace "hello-helidon" deleted

</div>
{{< /clipboard >}}
1. Verify that the `hello-helidon` namespace has been deleted.
{{< clipboard >}}
<div class="highlight">

    $ kubectl get ns hello-helidon

    # Expected response
    Error from server (NotFound): namespaces "hello-helidon" not found

</div>
{{< /clipboard >}}

## Uninstall Verrazzano

1. Delete the Verrazzano custom resource. This will uninstall the Verrazzano platform operator and all of the currently installed components.
{{< clipboard >}}
<div class="highlight">

    $ vz uninstall

</div>
{{< /clipboard >}}

2. Wait for the uninstall to complete.
   The uninstall logs from the Verrazzano platform operator will be streamed to the command window until the uninstall has completed or until the default timeout (20m) has been reached.

## Next steps

See the [Verrazzano Example Applications]({{< relref "/docs/samples/_index.md" >}}).
