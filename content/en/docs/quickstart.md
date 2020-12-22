---
title: "Quick Start"
description: "Instructions for getting started with Verrazzano"
weight: 2
---


### Prerequisites

The Quick Start assumes that you have already installed a
[Kubernetes](https://kubernetes.io/) cluster.  Verrazzano has been tested on
[Oracle Cloud Infrastructure Container Engine for Kubernetes](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) (OKE) and
[Oracle Linux Cloud Native Environment](https://docs.oracle.com/en/operating-systems/olcne/) (OLCNE); it is possible that it can be configured to work on other Kubernetes
environments.

Verrazzano requires the following:
* A Kubernetes cluster and a compatible `kubectl`.
    * Verrazzano has been tested only on the following versions of Kubernetes: 1.17.x and 1.18.x.
    * Other versions have not been tested and are _not_ guaranteed to work.
* At least 2 CPUs, 100GB disk storage, and 16GB RAM available on the Kubernetes worker nodes.

### Install the Verrazzano Platform Operator

Verrazzano provides a Kubernetes [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  The operator works with a
[custom resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) defined in the cluster.
You can install, uninstall, and update Verrazzano installations by updating the
[Verrazzano custom resource]({{< relref "reference/api/verrazzano/verrazzano.md" >}}).
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
your Kubernetes cluster.  Verrazzano currently supports a default production
profile and a development (dev) profile suitable for evaluation.  

The development profile has the following characteristics:
* Magic (xip.io) DNS
* Self-signed certificates
* Shared observability stack used by the system components and all applications
* Ephemeral storage for the observability stack (if the pods are restarted, you lose all of your logs and metrics)
* Single-node, reduced memory Elasticsearch cluster

To install Verrazzano, follow these steps:

1. Install Verrazzano with its dev profile.

    ```
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

## Deploy an example application

The [Hello World Helidon](https://github.com/verrazzano/verrazzano/blob/master/examples/hello-helidon/README.md)
example application provides a simple *Hello World* REST service written with [Helidon](https://helidon.io).
For more information and the code of this application, see the [Verrazzano examples](https://github.com/verrazzano/examples).

To deploy the Hello World Helidon example application, follow these steps:

1. Deploy the Verrazzano Application Model and Verrazzano Application Binding for the example application.

   ```shell
   $ kubectl apply \
      -f {{< ghlink raw=true path="examples/hello-helidon/hello-world-model.yaml" >}} \
      -f {{< ghlink raw=true path="examples/hello-helidon/hello-world-binding.yaml" >}}
   ```


   This creates the Verrazzano Application Model and Verrazzano Application Binding, waits for the pods in the `greet` namespace to be
   ready, and calls one of the endpoints provided by the REST service implemented by the example application.

1. Verify that the Verrazzano Application Model and Verrazzano Application Binding resources were created in the `default` namespace.

   ```shell
    $ kubectl get vm
    NAME                AGE
    hello-world-model   4m25s
    $ kubectl get vb
    NAME                  AGE
    hello-world-binding   4m8s
   ```

1. Verify that the `greet` namespace has been created.

   ```shell
   $ kubectl get ns greet
   NAME    STATUS   AGE
   greet   Active   5m44s
   ```

1. Verify that all the objects have started in the `greet` namespace.

    ```shell
    $kubectl get all -n greet
    NAME                                          READY   STATUS    RESTARTS   AGE
    pod/hello-world-application-868978f7b-fkcgg   3/3     Running   0          6m35s

    NAME                              TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
    service/hello-world-application   ClusterIP   10.96.240.190   <none>        8080/TCP   6m36s

    NAME                                      READY   UP-TO-DATE   AVAILABLE   AGE
    deployment.apps/hello-world-application   1/1     1            1           6m37s
    ```

1. Get the IP address and port number for calling the REST service.

   To get the `EXTERNAL-IP` address for the `istio-ingressgateway` service:

    ```
    SERVER=$(kubectl get service -n istio-system istio-ingressgateway -o json | jq -r '.status.loadBalancer.ingress[0].ip')
    PORT=80
    ```

1. Use the IP address and port number to call the following endpoints of the greeting REST service:

    ```
    # Get default message
    $ curl -s -X GET http://"${SERVER}":"${PORT}"/greet
    {"message":"Hello World!"}

    # Get message for Robert:
    $ curl -s -X GET http://"${SERVER}":"${PORT}"/greet/Robert
    {"message":"Hello Robert!"}

    # Change the message:
    $ curl -s -X PUT -H "Content-Type: application/json" -d '{"greeting" : "Hallo"}' http://"${SERVER}":"${PORT}"/greet/greeting

    # Get message for Robert again:
    $ curl -s -X GET http://"${SERVER}":"${PORT}"/greet/Robert
    {"message":"Hallo Robert!"}
    ```

### Uninstall the example application

To uninstall the Hello World Helidon example application, delete the Verrazzano Application Model and Verrazzano Application Binding
for the example application.

1. Delete the Verrazzano Application Binding for the example application.

   ```shell
   $ kubectl delete \
      -f {{< ghlink raw=true path="examples/hello-helidon/hello-world-binding.yaml" >}}
    ```

1. Delete the Verrazzano Application Model for the example application.

   ```shell
   $ kubectl delete \
      -f {{< ghlink raw=true path="examples/hello-helidon/hello-world-model.yaml" >}} \
   verrazzanobinding.verrazzano.io "hello-world-model" deleted
    ```

1. Verify that the `greet` namespace has been deleted.

   ```shell
   $ kubectl get ns greet
   Error from server (NotFound): namespaces "greet" not found
   ```

### Uninstall Verrazzano

To uninstall Verrazzano, follow these steps:

1. Delete the Verrazzano custom resource.

    ```shell
    kubectl delete verrazzano example-verrazzano
    ```

    {{< alert title="NOTE" color="info" >}}
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
