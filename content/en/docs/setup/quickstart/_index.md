---
title: "Quick Start"
weight: 1
aliases:
  - /docs/quickstart
---

The Quick Start assumes that you have already installed a
[Kubernetes](https://kubernetes.io/) cluster. For instructions on preparing Kubernetes
platforms for installing Verrazzano, see [Platform Setup]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}}).
For detailed installation instructions, see the [Installation Guides]({{< relref "/docs/setup/install" >}}).

**NOTE**: If you just created the cluster, then you must wait until your nodes reach `Ready` status before installing Verrazzano.

<br>

Getting up and running quickly with Verrazzano is as easy as [1](#1-install-cli) - [2](#2-install-verrazzano) - [3](#3-deploy-an-application):

![QS steps](/docs/images/QS-numbers.png)

## 1. Install CLI

The Verrazzano command-line tool, `vz`, is available for Linux and Mac systems.

Download the binary you want from the [Releases](https://github.com/verrazzano/verrazzano/releases/) page.

   For example, to download the latest release for Linux AMD64 machines:
   {{< clipboard >}}
   <div class="highlight">

        $ curl -LO {{<release_asset_url linux-amd64.tar.gz>}}

   </div>
   {{< /clipboard >}}

Unpack and copy the `vz` binary.
{{< clipboard >}}
<div class="highlight">

      $ tar xvf verrazzano-{{<verrazzano_development_version>}}-linux-amd64.tar.gz

</div>
{{< /clipboard >}}

  The following command needs to be run as root.

{{< clipboard >}}
<div class="highlight">

      $ sudo cp verrazzano-{{<verrazzano_development_version>}}/bin/vz /usr/local/bin
</div>
{{< /clipboard >}}

## 2. Install Verrazzano

You install Verrazzano by creating a Verrazzano custom resource in your Kubernetes cluster.
Verrazzano currently supports several [installation profiles]({{< relref "/docs/setup/install/perform/profiles.md" >}}).

Using the Quick Start, you'll install the `dev` profile, which is suitable for evaluation.

{{< alert title="NOTE" color="primary" >}}Because the `dev` profile installs self-signed certificates, when installing Verrazzano on macOS, you might see: **Your connection is not private**. For a workaround, see this [FAQ]({{< relref "/docs/troubleshooting/faq.md#enable-google-chrome-to-accept-self-signed-verrazzano-certificates" >}}).
{{< /alert >}}


Install Verrazzano with its `dev` profile.
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

Wait for the installation to complete.
   Installation logs will be streamed to the command window until the installation has completed
   or until the default timeout (30m) has been reached.

**NOTE**: For some applications, the Kiali console may show warnings for objects that replicate hostname/port configurations across multiple IngressTraits. These warnings do not impact functionality and can be suppressed with the following [component override]({{< relref "docs/applications/oam/deploy-app.md#suppress-kiali-console-warnings" >}}).

## 3. Deploy an application

The [Hello World Helidon]({{< relref "/docs/examples/hello-helidon/_index.md" >}})
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


2. Apply the `hello-helidon` resources to deploy the application.
{{< clipboard >}}
<div class="highlight">

    $ kubectl apply -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-comp.yaml >}} -n hello-helidon
    $ kubectl apply -f {{< release_source_url raw=true path=examples/hello-helidon/hello-helidon-app.yaml >}} -n hello-helidon

</div>
{{< /clipboard >}}

3. Wait for the application to be ready.
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

4. Save the host name of the load balancer exposing the application's REST service endpoints.
{{< clipboard >}}
<div class="highlight">

    $ HOST=$(kubectl get gateways.networking.istio.io hello-helidon-hello-helidon-gw \
        -n hello-helidon \
        -o jsonpath='{.spec.servers[0].hosts[0]}')

</div>
{{< /clipboard >}}

5. Get the default message.
{{< clipboard >}}
<div class="highlight">

    $ curl -sk \
        -X GET \
        "https://${HOST}/greet"

    # Expected response
    {"message":"Hello World!"}

</div>
{{< /clipboard >}}


## Next steps

See the [Verrazzano Example Applications]({{< relref "/docs/examples/_index.md" >}}).
