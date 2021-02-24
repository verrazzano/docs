---
title: "Quick Start"
description: "Instructions for getting started with Verrazzano"
weight: 2
---


### Prerequisites

The Quick Start assumes that you have already installed a
[Kubernetes](https://kubernetes.io/) cluster. For instructions on preparing Kubernetes
platforms for installing Verrazzano, see [Platform Setup]({{< relref "/docs/setup/platforms/_index.md" >}}). For
detailed installation instructions, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md" >}}).

Verrazzano requires the following:
* A Kubernetes cluster and a compatible `kubectl`.
    * Verrazzano has been tested _only_ on the following versions of Kubernetes: 1.17.x and 1.18.x.
    * Other versions have not been tested and are not guaranteed to work.
* At least 2 CPUs, 100GB disk storage, and 16GB RAM available on the Kubernetes worker nodes.

### Install the Verrazzano platform operator

Verrazzano provides a Kubernetes [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  The operator works with a
[custom resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) defined in the cluster.
You can install, uninstall, and update Verrazzano installations by updating the
[Verrazzano custom resource]({{< relref "../reference/api/verrazzano/verrazzano.md" >}}).
The [Verrazzano platform operator](https://github.com/verrazzano/verrazzano-platform-operator) controller will apply the configuration from the custom resource to the cluster for you.

To install the Verrazzano platform operator, follow these steps:

1. Deploy the Verrazzano platform operator.

    ```shell
    kubectl apply -f https://github.com/verrazzano/verrazzano/releases/latest/download/operator.yaml
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

### Install Verrazzano


You install Verrazzano by creating a Verrazzano custom resource in
your Kubernetes cluster.  Verrazzano currently supports a default production (`prod`)
profile and a development (`dev`) profile suitable for evaluation.  

The development profile has the following characteristics:
* Magic (xip.io) DNS
* Self-signed certificates
* Shared observability stack used by the system components and all applications
* Ephemeral storage for the observability stack (if the pods are restarted, you lose all of your logs and metrics)
* Single-node, reduced memory Elasticsearch cluster

To install Verrazzano, follow these steps:

1. Install Verrazzano with its `dev` profile.

    ```shell
    kubectl apply -f - <<EOF
    apiVersion: install.verrazzano.io/v1alpha1
    kind: Verrazzano
    metadata:
      name: example-verrazzano
    spec:
      profile: dev
    EOF
    ```

1. Wait for the installation to complete.
    ```shell
    kubectl wait \
        --timeout=20m \
        --for=condition=InstallComplete \
        verrazzano/example-verrazzano
    ```

1. (Optional) View the installation logs.

    The Verrazzano operator launches a Kubernetes [job](https://kubernetes.io/docs/concepts/workloads/controllers/job/) to install Verrazzano.  You can view the installation logs from that job with the following command:

    ```shell
    kubectl logs -f \
        $( \
          kubectl get pod  \
              -l job-name=verrazzano-install-example-verrazzano \
              -o jsonpath="{.items[0].metadata.name}" \
        )
    ```

### Deploy an example application

The [Hello World Helidon](https://github.com/verrazzano/verrazzano/blob/master/examples/hello-helidon/README.md)
example application provides a simple *Hello World* REST service written with [Helidon](https://helidon.io).
For more information and the code of this application, see the [Verrazzano examples](https://github.com/verrazzano/examples).

To deploy the Hello World Helidon example application, follow these steps:



1. Create a namespace for the example application and add a label identifying the namespace as managed by Verrazzano.

   ```shell
   $ kubectl create namespace hello-helidon
   $ kubectl label namespace hello-helidon verrazzano-managed=true
   ```

1. Apply the hello-helidon resources to deploy the application.

   ```shell
   $ kubectl apply -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-comp.yaml" >}}
   $ kubectl apply -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-app.yaml" >}}
   ```

1. Wait for the application to be ready.

   ```shell
   $ kubectl wait --for=condition=Ready pods --all -n hello-helidon --timeout=300s
   pod/hello-helidon-workload-977cbbc94-z22ls condition met
   ```
   This creates the Verrazzano OAM component application resources for the example, waits for the pods in the `hello-helidon`
   namespace to be ready.

1.  Save the host name of the load balancer exposing the application's REST service endpoints.
    ```shell script
    $ HOST=$(kubectl get gateway hello-helidon-hello-helidon-appconf-gw -n hello-helidon -o jsonpath='{.spec.servers[0].hosts[0]}')
    ```

1.  Get the default message.
    ```shell script
    $ curl -sk -X GET "https://${HOST}/greet"

    {"message":"Hello World!"}
    ```


### Uninstall the example application

To uninstall the Hello World Helidon example application, follow these steps.

1. Delete the Verrazzano application resources.

   ```shell
   $ kubectl delete -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-comp.yaml" >}}
   $ kubectl delete -f {{< ghlink raw=true path="examples/hello-helidon/hello-helidon-app.yaml" >}}
    ```

1. Delete the example namespace.

   ```shell
   $ kubectl delete namespace hello-helidon
   namespace "hello-helidon" deleted
    ```

1. Verify that the `hello-helidon` namespace has been deleted.

   ```shell
   $ kubectl get ns hello-helidon
   Error from server (NotFound): namespaces "hello-helidon" not found
   ```

### Uninstall Verrazzano

To uninstall Verrazzano, follow these steps:

1. Delete the Verrazzano custom resource.

    ```shell
    kubectl delete verrazzano example-verrazzano
    ```

   {{< alert title="NOTE" color="tip" >}}
   This command blocks until the uninstall has completed.  To follow the progress,
   you can view the uninstall logs.
   {{< /alert >}}

1. (Optional) View the uninstall logs.

    The Verrazzano operator launches a Kubernetes [job](https://kubernetes.io/docs/concepts/workloads/controllers/job/) to delete the Verrazzano installation.  You can view the uninstall logs from that job with the following command:

    ```shell
    kubectl logs -f \
        $( \
          kubectl get pod  \
              -l job-name=verrazzano-uninstall-example-verrazzano \
              -o jsonpath="{.items[0].metadata.name}" \
        )
    ```
### Next steps

For more example applications, see [Verrazzano Examples](https://github.com/verrazzano/verrazzano/tree/master/examples).
