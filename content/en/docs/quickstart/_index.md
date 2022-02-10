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
- Review the list of the [software versions supported]({{< relref "/docs/setup/prereqs.md#supported-software-versions" >}}) and [installed]({{< relref "/docs/setup/prereqs.md#installed-components" >}}) by Verrazzano.
- For detailed installation instructions, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md" >}}).


## Install the Verrazzano platform operator

Verrazzano provides a Kubernetes [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  The operator works with a
[custom resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) defined in the cluster.
You can install, uninstall, and update Verrazzano installations by updating the
[Verrazzano custom resource]({{< relref "/docs/reference/api/verrazzano/verrazzano.md" >}}).
The [Verrazzano platform operator](https://github.com/verrazzano/verrazzano) controller will apply the configuration from the custom resource to the cluster for you.

**NOTE**: If you just created the cluster, then you must wait until your nodes reach Ready status before installing Verrazzano.

To install the Verrazzano platform operator:

1. Deploy the Verrazzano platform operator.
    ```
    $ kubectl apply -f {{<release_asset_url operator.yaml>}}
    ```

1. Wait for the deployment to complete.

    ```
    $ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator

    # Sample output
    deployment "verrazzano-platform-operator" successfully rolled out
    ```

1. Confirm that the operator pod is correctly defined and running.

    ```
    $ kubectl -n verrazzano-install get pods

    # Sample output
    NAME                                            READY   STATUS    RESTARTS   AGE
    verrazzano-platform-operator-59d5c585fd-lwhsx   1/1     Running   0          114s
    ```

## Install Verrazzano


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

To install Verrazzano:

1. Install Verrazzano with its `dev` profile.

    ```
    $ kubectl apply -f - <<EOF
    apiVersion: install.verrazzano.io/v1alpha1
    kind: Verrazzano
    metadata:
      name: example-verrazzano
    spec:
      profile: dev
    EOF
    ```

1. Wait for the installation to complete.
    ```
    $ kubectl wait \
        --timeout=20m \
        --for=condition=InstallComplete \
        verrazzano/example-verrazzano
    ```

1. (Optional) View the installation logs.

    The Verrazzano operator launches a Kubernetes [job](https://kubernetes.io/docs/concepts/workloads/controllers/job/) to install Verrazzano.  You can view the installation logs from that job with the following command:

    ```
    $ kubectl logs -n verrazzano-install \
        -f $(kubectl get pod \
        -n verrazzano-install \
        -l app=verrazzano-platform-operator \
        -o jsonpath="{.items[0].metadata.name}") | grep '"operation":"install"'
    ```

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
   $ kubectl apply -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-comp.yaml" >}}
   $ kubectl apply -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-app.yaml" >}}
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
   This creates the Verrazzano OAM Component application resources for the example, waits for the pods in the `hello-helidon`
   namespace to be ready.

1.  Save the host name of the load balancer exposing the application's REST service endpoints.
    ```
    $ HOST=$(kubectl get gateway hello-helidon-hello-helidon-appconf-gw \
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

To uninstall the Hello World Helidon example application:

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

To uninstall Verrazzano:

1. Delete the Verrazzano custom resource.

    ```
    $ kubectl delete verrazzano example-verrazzano
    ```

   {{< alert title="NOTE" color="tip" >}}
   This command blocks until the uninstall has completed.  To follow the progress,
   you can view the uninstall logs.
   {{< /alert >}}

1. (Optional) View the uninstall logs.

    The Verrazzano operator launches a Kubernetes [job](https://kubernetes.io/docs/concepts/workloads/controllers/job/) to delete the Verrazzano installation.  You can view the uninstall logs from that job with the following command:

    ```
    $ kubectl logs -n verrazzano-install -f \
        $( \
          kubectl get pod \
              -n verrazzano-install \
              -l job-name=verrazzano-uninstall-example-verrazzano \
              -o jsonpath="{.items[0].metadata.name}" \
        )
    ```
## Next steps

See the [Verrazzano Example Applications]({{< relref "/docs/samples/_index.md" >}}).
