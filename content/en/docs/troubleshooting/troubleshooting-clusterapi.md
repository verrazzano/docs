---
title: "OCNE Cluster Creation Issues"
description: "Troubleshoot issues when creating OCNE clusters"
weight: 5
draft: false
---

If you encounter a problem with the OCNE clusters created in the console (using the [clusterAPI component]({{< relref "/docs/setup/provision-cluster/capi" >}})), here are some techniques you can use to diagnose and solve the issue.

### Assess the condition of the clusterAPI component

You can gather information about the clusterAPI component by reviewing its log files and by checking the status of clusterAPI custom resources on the admin cluster. In the console, the admin cluster is the *local* cluster.

**Review clusterAPI log files**

The clusterAPI component creates four clusterAPI pods within the `verrazzano-capi` namespace and each pod generates a separate log file. Review the log files to determine the cause of the issue.

Where `nnnn` is the unique ID for the pod.

To view the clusterAPI controller log file, use the following command:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-capi capi-controller-manager-<nnnn>
```
{{< /clipboard >}}
</div>

To view the clusterAPI OCI provider log file, use the following command:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-capi capoci-controller-manager-<nnnn>
```
{{< /clipboard >}}
</div>

To view the clusterAPI control plane provider log file, use the following command:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-capi capi-ocne-control-plane-controller-manager-<nnnn>
```
{{< /clipboard >}}
</div>

To view the clusterAPI bootstrap provider log file, use the following command:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-capi capi-ocne-bootstrap-controller-manager-<nnnn>
```
{{< /clipboard >}}
</div>

**Review clusterAPI Kubernetes custom resources**

On the admin cluster, use `kubectl` to check the status of the clusterAPI custom resource.

To see the status of the clusterAPI Kubernetes custom resource cluster, use the following command:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl get clusters.cluster.x-k8s.io -A
```
{{< /clipboard >}}

The cluster status should be `Provisioned`.

To see the status of the clusterAPI Kubernetes custom resource machine, use the following command:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl get machines -A
```
{{< /clipboard >}}

The status of each machine should be `Running`. 

### Verify the status of OCI resources

When creating clusters, Verrazzano creates the following resources in the associated OCI compartment:

* [A network load balancer](https://docs.oracle.com/en-us/iaas/Content/NetworkLoadBalancer/NetworkLoadBalancers/list-network-load-balancer.htm)
* [Compute instances for each control plane node and worker node](https://docs.oracle.com/en-us/iaas/Content/Compute/home.htm)

If one of these resources was not created, or was created but is now experiencing issues, it can affect the rest of the cluster.

You can check the status of the required OCI resources in the OCI console or by [reviewing the log files](#assess-the-condition-of-the-clusterapi-component) for the clusterAPI controller.

Causes may include:

* OCI resource limits were reached: Cluster creation will fail if it needs to create more resources than allowed by your OCI tenancy. Check your OCI service limits to see if you exceeded its limits. If you need to request a service limit increase, see [Requesting a Service Limit Increase](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/servicelimits.htm#Requesti).

* Connectivity issues: Make sure your virtual cloud network is configured properly.

* The network load balancer is in a critical state: The network load balancer may temporarily enter a critical state during initial cluster creation until the Kubernetes API server is up. If it remains in a critical state, then one of the following issues may have occurred:
    * Traffic between the network load balancer and the OCNE control plane node is blocked over port 6443.

    * The OCNE API server did not start, possibly because OCNE dependencies failed to install.

* Node creation failed:
    * The OCI credentials are invalid: Check for errors under Kubernetes events in the namespace where cluster objects are present or in the OCI provider log file.

    * The Image ID used to deploy templates is invalid.

    * Worker nodes only: Worker nodes began provisioning after the control node plane entered the `Running` state.
        * If OCNE dependencies failed to install on the control plane node, worker nodes remain in the `Pending` state and do not get created. Check the `cloud-init` log files on the control plane nodes to determine the cause.

Also, you should confirm that pods are running on the workload cluster. From the console, download the kubeconfig file for the workload cluster and run the following command:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl --kubeconfig <workload-cluster-kubeconfig> get pods -A
```
{{< /clipboard >}}
</div>

If the status of any of the pods is not `Running`, run the following command to identify the error:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl describe pod <pod-name>
```
{{< /clipboard >}}
</div>


{{< alert title="NOTE" color="primary" >}}
You can also refer to the [Cluster API documentation](https://cluster-api.sigs.k8s.io/user/troubleshooting.html) for generic information on troubleshooting and known issues. Be aware that because the clusterAPI component is specific to Verrazzano, certain issues or solutions may not apply.
{{< /alert >}}