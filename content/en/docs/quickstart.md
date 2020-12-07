---
title: "Quick Start"
description: "Instructions for getting started with Verrazzano"
weight: 2
---

Verrazzano is an end-to-end enterprise container platform for deploying cloud-native and traditional applications in multi-cloud and hybrid environments. It is made up of a curated set of open source components – many that you may already use and trust, and some that were written specifically to pull together all of the pieces that make Verrazzano a cohesive and easy to use platform.

Verrazzano includes the following capabilities:

* Hybrid and multi-cluster workload management
* Special handling for WebLogic, Coherence, and Helidon applications
* Multi-cluster infrastructure management
* Integrated and pre-wired application monitoring
* Integrated security
* DevOps and GitOps enablement

{{< alert title="NOTE" color="warning" >}}
This is a developer preview release of Verrazzano. It is intended for installation in a single cluster on
[Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE)](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm)
or [Oracle Linux Cloud Native Environment (OLCNE)](https://docs.oracle.com/en/operating-systems/olcne/).
You should install Verrazzano only in a cluster that can be safely deleted when your evaluation is complete.
{{< /alert >}}

## Install Verrazzano

To install Verrazzano, follow these steps:

1. Create an [Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE)](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) cluster.
1. Launch [OCI Cloud Shell](https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/cloudshellgettingstarted.htm).
1. Set up a [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) file in the OCI Cloud Shell for the OKE cluster. See these detailed [instructions](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengdownloadkubeconfigfile.htm).
1. Deploy the Verrazzano platform operator.

    ```
    kubectl apply -f https://github.com/verrazzano/verrazzano/releases/latest/download/operator.yaml
    ```
1. Install Verrazzano with its default configuration.

    ```
    kubectl apply -f - <<EOF
    apiVersion: install.verrazzano.io/v1alpha1
    kind: Verrazzano
    metadata:
      name: example-verrazzano
    EOF
    ```
1. Wait for the installation to complete.
    ```
    kubectl wait \
        --timeout=20m \
        --for=condition=InstallComplete \
        verrazzano/example-verrazzano
    ```

1. View the installation logs (optional).

    The Verrazzano operator launches a Kubernetes [job](https://kubernetes.io/docs/concepts/workloads/controllers/job/) to install Verrazzano.  You can view the installation logs from that job with the following command:

    ```
    kubectl logs -f \
        $( \
          kubectl get pod  \
              -l job-name=verrazzano-install-example-verrazzano \
              -o jsonpath="{.items[0].metadata.name}" \
        )
    ```

## Uninstall Verrazzano

To uninstall Verrazzano, follow these steps:

1. Delete the Verrazzano custom resource.

    ```
    kubectl delete verrazzano example-verrazzano
    ```

    {{< alert title="NOTE" color="info" >}}
    This command blocks until the uninstall has completed.  To follow the progress
    you can view the uninstall logs.
    {{< /alert >}}

1. View the uninstall logs (optional).

    The Verrazzano operator launches a Kubernetes [job](https://kubernetes.io/docs/concepts/workloads/controllers/job/) to delete the Verrazzano installation.  You can view the uninstall logs from that job with the following command:

    ```
    kubectl logs -f \
        $( \
          kubectl get pod  \
              -l job-name=verrazzano-uninstall-example-verrazzano \
              -o jsonpath="{.items[0].metadata.name}" \
        )
    ```

## Deploy the Example Applications

To deploy the example applications, please see the following instructions:

* [Helidon Hello World](https://github.com/verrazzano/verrazzano/blob/master/examples/hello-helidon/README.md)
* [Bob's Books](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books/README.md)
* [Helidon Sock Shop](https://github.com/verrazzano/verrazzano/blob/master/examples/sock-shop/README.md)
* [ToDo List](https://github.com/verrazzano/examples/blob/master/todo-list/README.md)

