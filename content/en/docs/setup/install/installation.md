---
title: "Installation Guide"
linkTitle: Install
description: "How to install Verrazzano"
weight: 9
draft: false
---

You can install Verrazzano in a single [Oracle Cloud Infrastructure Container Engine for Kubernetes](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) (OKE) cluster or
an [Oracle Linux Cloud Native Environment](https://docs.oracle.com/en/operating-systems/olcne/) (OLCNE) deployment.

For an OKE cluster, you have two DNS choices:
[xip.io](http://xip.io/) or
[Oracle OCI DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/dnszonemanagement.htm). OLCNE currently supports only a manual DNS.

{{< alert title="NOTE" color="warning" >}}
You should install this developer preview release of Verrazzano only in a cluster that can be safely deleted when your evaluation is complete.
{{< /alert >}}

Verrazzano requires the following:

- A Kubernetes cluster and a compatible `kubectl`.
- At least 2 CPUs, 100GB disk storage, and 16GB RAM available on the Kubernetes worker nodes.


**NOTE**: Verrazzano has been tested _only_ on the following versions of Kubernetes: 1.17.x and 1.18.x.  Other versions have not been tested and are not guaranteed to work.


### Prepare for the install

To prepare for installing on OCI Container Engine for Kubernetes, see [Prepare for the OCI install](../../platforms/oci/oci).

To prepare for installing on OLCNE, see [Prepare for the OCLNE install](../../platforms/olcne/olcne).

### Install the Verrazzano Platform Operator

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  You can install,
uninstall, and update Verrazzano installations by updating the
[Verrazzano custom resource](../../../reference/api/verrazzano/verrazzano).

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

### Perform the install

For a complete description of Verrazzano configuration options, see the [Verrazzano Custom Resource Definition](../../../reference/api/verrazzano/verrazzano).

According to your DNS choice, install Verrazzano using one of the following methods.

{{< tabs tabTotal="2" tabID="2" tabName1="xip.io" tabName2="OCI DNS" >}}
{{< tab tabNum="1" >}}
<br>

##### Install using xip.io
The [install-default.yaml](https://github.com/verrazzano/verrazzano/blob/develop/operator/config/samples/install-default.yaml) file provides a template for a default xip.io installation.

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
```


Run the following commands:
```
kubectl apply -f https://github.com/verrazzano/verrazzano/releases/latest/download/operator.yaml 
kubectl apply -f https://raw.githubusercontent.com/verrazzano/verrazzano/master/operator/config/samples/install-default.yaml
kubectl wait --timeout=20m --for=condition=InstallComplete verrazzano/my-verrazzano
```

{{< /tab >}}
{{< tab tabNum="2" >}}
<br>

##### Install using OCI DNS

###### Prerequisites
* A DNS zone is a distinct portion of a domain namespace. Therefore, ensure that the zone is appropriately associated with a parent domain.
For example, an appropriate zone name for parent domain `v8o.example.com` domain is `us.v8o.example.com`.
* Create an OCI DNS zone using the OCI Console or the OCI CLI.  

  CLI example:
  ```
  oci dns zone create -c <compartment ocid> --name <zone-name-prefix>.v8o.oracledx.com --zone-type PRIMARY
  ```

###### Installation

Installing Verrazzano on OCI DNS requires some configuration settings to create DNS records.
The [install-oci.yaml](https://github.com/verrazzano/verrazzano/blob/master/operator/config/samples/install-oci.yaml) file provides a template of a Verrazzano custom resource for an OCI DNS installation. Edit this custom resource and provide values for the following configuration settings:

* `spec.environmentName`
* `spec.certificate.acme.emailAddress`
* `spec.dns.oci.ociConfigSecret`
* `spec.dns.oci.dnsZoneCompartmentOCID`
* `spec.dns.oci.dnsZoneOCID`
* `spec.dns.oci.dnsZoneName`

For the full configuration information for an installation, see the [Verrazzano Custom Resource Definition](../../../reference/api/verrazzano/verrazzano/).

When you use the OCI DNS installation, you need to provide a Verrazzano name in the Verrazzano custom resource
 (`spec.environmentName`) that will be used as part of the domain name used to access Verrazzano
ingresses.  For example, you could use `sales` as an `environmentName`, yielding
`sales.us.v8o.example.com` as the sales-related domain (assuming the domain and zone names listed
previously).

Run the following commands:
```
kubectl apply -f https://github.com/verrazzano/verrazzano/releases/latest/download/operator.yaml 
kubectl apply -f https://raw.githubusercontent.com/verrazzano/verrazzano/master/operator/config/samples/install-oci.yaml
kubectl wait --timeout=20m --for=condition=InstallComplete verrazzano/my-verrazzano
```
{{< /tab >}}
{{< /tabs >}}


To monitor the console log output of the installation, run the following command:
```
    kubectl logs -f $(kubectl get pod -l job-name=verrazzano-install-my-verrazzano -o jsonpath="{.items[0].metadata.name}")
```

### Verify the install

Verrazzano installs multiple objects in multiple namespaces. In the `verrazzano-system` namespaces, all the pods in the `Running` state, does not guarantee, but likely indicates that Verrazzano is up and running.
```
kubectl get pods -n verrazzano-system
verrazzano-admission-controller-84d6bc647c-7b8tl   1/1     Running   0          5m13s
verrazzano-cluster-operator-57fb95fc99-kqjll       1/1     Running   0          5m13s
verrazzano-monitoring-operator-7cb5947f4c-x9kfc    1/1     Running   0          5m13s
verrazzano-operator-b6d95b4c4-sxprv                1/1     Running   0          5m13s
vmi-system-api-7c8654dc76-2bdll                    1/1     Running   0          4m44s
vmi-system-es-data-0-6679cf99f4-9p25f              2/2     Running   0          4m44s
vmi-system-es-data-1-8588867569-zlwwx              2/2     Running   0          4m44s
vmi-system-es-ingest-78f6dfddfc-2v5nc              1/1     Running   0          4m44s
vmi-system-es-master-0                             1/1     Running   0          4m44s
vmi-system-es-master-1                             1/1     Running   0          4m44s
vmi-system-es-master-2                             1/1     Running   0          4m44s
vmi-system-grafana-5f7bc8b676-xx49f                1/1     Running   0          4m44s
vmi-system-kibana-649466fcf8-4n8ct                 1/1     Running   0          4m44s
vmi-system-prometheus-0-7f97ff97dc-gfclv           3/3     Running   0          4m44s
vmi-system-prometheus-gw-7cb9df774-48g4b           1/1     Running   0          4m44s
```

### Installation profiles

Verrazzano supports two installation profiles:  development (dev) and production (prod). The production profile, which is the default, provides a 3-node Elasticsearch and persistent storage for the Verrazzano Monitoring Instance (VMI). The development profile provides a single node Elasticsearch and no persistent storage for the VMI.   

To use the development profile, specify the following in the rKkubernetes manifest for the Verrazzano custom resource:

```
spec:
  profile: dev
```

The [install-dev.yaml](https://github.com/verrazzano/verrazzano/blob/develop/operator/config/samples/install-dev.yaml) file provides a template for a dev profile installation.

#### (Optional) Install the example applications
Example applications are located [here](https://github.com/verrazzano/verrazzano/tree/master/examples).

##### To get the consoles URLs and credentials, see [Operations](../../../operations).

### Uninstall Verrazzano

To delete a Verrazzano installation, run the following commands:

```
# Get the name of the Verrazzano custom resource
kubectl get verrazzano

# Delete the Verrazzano custom resource
kubectl delete verrazzano <name of custom resource>
```

To monitor the console log of the uninstall, run the following command:

```
kubectl logs -f $(kubectl get pod -l job-name=verrazzano-uninstall-my-verrazzano -o jsonpath="{.items[0].metadata.name}")
```

## Known Issues
#### OKE Missing Security List Ingress Rules

The install scripts perform a check, which attempts access through the ingress ports.  If the check fails, then the install will exit and you will see error messages like this:

`ERROR: Port 443 is NOT accessible on ingress(132.145.66.80)!  Check that security lists include an ingress rule for the node port 31739.`

On an OKE install, this may indicate that there is a missing ingress rule or rules.  To verify and fix the issue, do the following:
  1. Get the ports for the `LoadBalancer` services.
     * Run `kubectl get services -A`.
     * Note the ports for the `LoadBalancer` type services.  For example `80:31541/TCP,443:31739/TCP`.
  2. Check the security lists in the OCI Console.
     * Go to `Networking/Virtual Cloud Networks`.
     * Select the related VCN.
     * Go to the `Security Lists` for the VCN.
     * Select the security list named `oke-wkr-...`.
     * Check the ingress rules for the security list.  There should be one rule for each of the destination ports named in the `LoadBalancer` services.  In the above example, the destination ports are `31541` & `31739`. We would expect the ingress rule for `31739` to be missing because it was named in the `ERROR` output.
     * If a rule is missing, then add it by clicking `Add Ingress Rules` and filling in the source CIDR and destination port range (missing port).  Use the existing rules as a guide.
