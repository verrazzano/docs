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
- Review the list of the [software versions supported]({{< relref "/docs/setup/prereqs.md#supported-software-versions" >}}) and [installed]({{< relref "/docs/setup/prereqs.md#installed-components" >}}) by Verrazzano.
- For detailed Verrazzano installation instructions, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md" >}}).

**NOTE**: If you just created the cluster, then you must wait until your nodes reach `Ready` status before installing Verrazzano.

## Install Verrazzano

Verrazzano provides a Kubernetes [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  The operator works with a
[custom resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) defined in the cluster.
You can install, uninstall, and update Verrazzano installations by updating the
[Verrazzano custom resource]({{< relref "/docs/reference/api/verrazzano/verrazzano.md" >}}).
The [Verrazzano platform operator](https://github.com/verrazzano/verrazzano) controller will apply the configuration from the custom resource to the cluster for you.

You install Verrazzano by creating a Verrazzano custom resource in
your Kubernetes cluster.  Verrazzano currently supports a default production (`prod`)
profile and a development (`dev`) profile suitable for evaluation.  

The development profile has the following characteristics:
* Wildcard (nip.io) DNS
* Self-signed certificates
* Shared observability stack used by the system components and all applications
* Ephemeral storage for the observability stack (if the pods are restarted, you lose all of your logs and metrics)
* Single-node, reduced memory OpenSearch cluster

{{< alert title="NOTE" color="warning" >}}Because the `dev` profile installs self-signed certificates, when installing Verrazzano on macOS, you might see: **Your connection is not private**. For a workaround, see this [FAQ]({{< relref "/docs/faq/FAQ#enable-google-chrome-to-accept-self-signed-verrazzano-certificates" >}}).
{{< /alert >}}

### Install Verrazzano using the [Verrazzano CLI]({{< relref "docs/setup/cli/_index.md" >}})

1. Install Verrazzano with its `dev` profile.
    ```
    $ vz install -f - <<EOF
    apiVersion: install.verrazzano.io/v1alpha1
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
    ```

2. Wait for the installation to complete.
   Installation logs will be streamed to the command window until the installation has completed
   or until the default timeout (30m) has been reached.

## Deploy an example application

The [Hello World Helidon]({{< relref "/docs/samples/hello-helidon/_index.md" >}})
example application provides a simple *Hello World* REST service written with [Helidon](https://helidon.io).
For more information and the code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).

To deploy the Hello World Helidon example application:



1. Create a namespace for the example application and add labels identifying the namespace as managed by Verrazzano and
enabled for Istio.

   ```
   $ kubectl create namespace hello-helidon
   $ kubectl label namespace hello-helidon verrazzano-managed=true istio-injection=enabled
   ```

1. Apply the `hello-helidon` resources to deploy the application.

   ```
   $ kubectl apply -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-comp.yaml" >}} -n hello-helidon
   $ kubectl apply -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-app.yaml" >}} -n hello-helidon
   ```

1. Wait for the application to be ready.

   ```
   $ kubectl wait \
       --for=condition=Ready pods \
       --all -n hello-helidon \
       --timeout=300s

   # Sample output
   pod/hello-helidon-deployment-78468f5f9c-czmp4 condition met
   ```
   This creates the Verrazzano OAM Component application resources for the example and waits for the pods in the `hello-helidon`
   namespace to be ready.

1.  Save the host name of the load balancer exposing the application's REST service endpoints.
    ```
    $ HOST=$(kubectl get gateways.networking.istio.io hello-helidon-hello-helidon-appconf-gw \
        -n hello-helidon \
        -o jsonpath='{.spec.servers[0].hosts[0]}')
    ```

1.  Get the default message.
    ```
    $ curl -sk \
        -X GET \
        "https://${HOST}/greet"

    # Expected response
    {"message":"Hello World!"}
    ```


## Uninstall the example application

1. Delete the Verrazzano application resources.

   ```
   $ kubectl delete -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-comp.yaml" >}}
   $ kubectl delete -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-app.yaml" >}}
    ```

1. Delete the example namespace.

   ```
   $ kubectl delete namespace hello-helidon

   # Expected response
   namespace "hello-helidon" deleted
    ```

1. Verify that the `hello-helidon` namespace has been deleted.

   ```
   $ kubectl get ns hello-helidon

   # Expected response
   Error from server (NotFound): namespaces "hello-helidon" not found
   ```

## Uninstall Verrazzano

1. Delete the Verrazzano custom resource. This will uninstall the Verrazzano platform operator and all of the currently installed components.

    ```
    $ vz uninstall
    ```

2. Wait for the uninstall to complete.
The Verrazzano operator launches a Kubernetes [job](https://kubernetes.io/docs/concepts/workloads/controllers/job/) to delete the Verrazzano installation.  
The uninstall logs from that job will be streamed to the command window until the uninstall has completed or until the default timeout (20m) has been reached.

## Next steps

See the [Verrazzano Example Applications]({{< relref "/docs/samples/_index.md" >}}).
