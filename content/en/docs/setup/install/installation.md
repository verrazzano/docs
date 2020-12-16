---
title: "Installation Guide"
linkTitle: "Install"
weight: 9
draft: false
---

Verrazzano has been tested on [Oracle Cloud Infrastructure Container Engine for Kubernetes (OKE)](https://docs.cloud.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengoverview.htm) and [Oracle Linux Cloud Native Environment (OCLNE)](https://docs.oracle.com/en/operating-systems/olcne/); it is possible that it can be configured to work on other Kubernetes environments.  

For an OCI OKE cluster, you have two DNS choices:
[xip.io](http://xip.io/) or
[Oracle OCI DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/dnszonemanagement.htm). OLCNE currently supports only a manual DNS.

> **NOTE**: You should install this alpha release of Verrazzano only in a cluster that can be safely deleted when your evaluation is complete.


Verrazzano requires the following:

- A Kubernetes cluster v1.16 or later and a compatible kubectl

- At least 2 CPUs, 100GB disk storage, and 16GB RAM available on the Kubernetes worker nodes.


## Prepare for the Install

To prepare for installing on OCI OKE, see the [OCI Prep instructions](../../platforms/oci).

To prepare for installing on OLCNE, see the [OLCNE Prep instructions](../../platforms/olcne).

## Install the Verrazzano Platform Operator

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  You can install,
uninstall, and update Verrazzano installations by updating the Verrazzano
[custom resource](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).

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

## Perform the install

According to your DNS choice, install Verrazzano using one of the following methods.
For a complete description of Verrazzano configuration options, see [Verrazzano Custom Resource](README.md#verrazzano-custom-resource).

{{< tabs tabTotal="3" tabID="2" tabName1="OCI OKE" tabName2="OLCNE" tabName3="Generic" >}}
{{< tab tabNum="1" >}}
<br>

#### OCI OKE Install

##### Install using xip.io
The [install-default.yaml](operator/config/samples/install-default.yaml) file provides a template for a default xip.io installation.

Run the following commands:
```
    kubectl apply -f operator/config/samples/install-default.yaml
    kubectl wait --timeout=20m --for=condition=InstallComplete verrazzano/my-verrazzano
```
Run the following command to monitor the console log output of the installation:
```
    kubectl logs -f $(kubectl get pod -l job-name=verrazzano-install-my-verrazzano -o jsonpath="{.items[0].metadata.name}")
```

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
The [install-oci.yaml](operator/config/samples/install-oci.yaml) file provides a template of a Verrazzano custom resource for an OCI DNS installation. Edit this custom resource and provide values for the following configuration settings:

* `spec.environmentName`
* `spec.certificate.acme.emailAddress`
* `spec.dns.oci.ociConfigSecret`
* `spec.dns.oci.dnsZoneCompartmentOCID`
* `spec.dns.oci.dnsZoneOCID`
* `spec.dns.oci.dnsZoneName`

See the [Verrazzano Custom Resource Definition](README.md#table-verrazzano-custom-resource-definition) table for a description of the Verrazzano custom resource.

When you use the OCI DNS installation, you need to provide a Verrazzano name in the Verrazzano custom resource
 (`spec.environmentName`) that will be used as part of the domain name used to access Verrazzano
ingresses.  For example, you could use `sales` as an `environmentName`, yielding
`sales.us.v8o.example.com` as the sales-related domain (assuming the domain and zone names listed
previously).

Run the following commands:
```
    kubectl apply -f operator/config/samples/install-oci.yaml
    kubectl wait --timeout=20m --for=condition=InstallComplete verrazzano/my-verrazzano
```
Run the following command if you want to monitor the console log output of the installation:
```
    kubectl logs -f $(kubectl get pod -l job-name=verrazzano-install-my-verrazzano -o jsonpath="{.items[0].metadata.name}")
```

{{< /tab >}}
{{< tab tabNum="2" >}}
<br>

#### OLCNE Install

During the Verrazzano install, these steps should be performed on the Oracle Linux Cloud Native Environment operator node.

Clone the Verrazzano install repository.
```
git clone https://github.com/verrazzano/verrazzano.git
cd verrazzano/install
```
If required, use the following commands to install `git`.
```
sudo yum install -y git
```
Edit the sample Verrazzano custom resource [install-olcne.yaml](operator/config/samples/install-olcne.yaml) file and provide the configuration settings for your OLCNE environment as follows:

- The value for `spec.environmentName` is a unique DNS subdomain for the cluster (for example, `myenv` in `myenv.mydomain.com`).
- The value for `spec.dns.external.suffix` is the remainder of the DNS domain (for example, `mydomain.com` in `myenv.mydomain.com`).
- Under `spec.ingress.verrazzano.nginxInstallArgs`, the value for `controller.service.externalIPs` is the IP address of `ingress-mgmt.<myenv>.<mydomain.com>` configured during DNS set up.
- Under  `spec.ingress.application.istioInstallArgs`, the value for `gateways.istio-ingressgateway.externalIPs` is the IP address of `ingress-verrazzano.<myenv>.<mydomain.com>` configured during DNS set up.

You will install Verrazzano using the `external` DNS type (the example custom resource for OLCNE is already configured to use `spec.dns.external`).

Set the following environment variables:

The value for `<path to valid Kubernetes config>` is typically `${HOME}/.kube/config`
```
export KUBECONFIG=$VERRAZZANO_KUBECONFIG
```

Run the following commands:
```
kubectl apply -f operator/deploy/operator.yaml
kubectl apply -f operator/config/samples/install-olcne.yaml
kubectl wait --timeout=20m --for=condition=InstallComplete verrazzano/my-verrazzano
```

Run the following command to monitor the console log output of the installation:
```
    kubectl logs -f $(kubectl get pod -l job-name=verrazzano-install-my-verrazzano -o jsonpath="{.items[0].metadata.name}")
```

{{< /tab >}}
{{< tab tabNum="3" >}}
<br>
Placeholder for Generic K8s install

{{< /tab >}}
{{< /tabs >}}



## Verify the install

Verrazzano installs multiple objects in multiple namespaces. In the `verrazzano-system` namespaces, all the pods in the `Running` state does not guarantee, but likely indicates that Verrazzano is up and running.
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

## Get the console URLs
Verrazzano installs several consoles.  You can get the ingress for the consoles with the following command:

`kubectl get ingress -A`

Simply prefix `https://` to the host name to get the URL.  For example `https://rancher.myenv.mydomain.com`

Following is an example of the ingresses:
```
   NAMESPACE           NAME                               HOSTS                                          ADDRESS          PORTS     AGE
   cattle-system       rancher                            rancher.myenv.mydomain.com                     128.234.33.198   80, 443   93m
   keycloak            keycloak                           keycloak.myenv.mydomain.com                    128.234.33.198   80, 443   69m
   verrazzano-system   verrazzano-operator-ingress        api.myenv.mydomain.com                         128.234.33.198   80, 443   81m
   verrazzano-system   vmi-system-api                     api.vmi.system.myenv.mydomain.com              128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-es-ingest               elasticsearch.vmi.system.myenv.mydomain.com    128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-grafana                 grafana.vmi.system.myenv.mydomain.com          128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-kibana                  kibana.vmi.system.myenv.mydomain.com           128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-prometheus              prometheus.vmi.system.myenv.mydomain.com       128.234.33.198   80, 443   80m
   verrazzano-system   vmi-system-prometheus-gw           prometheus-gw.vmi.system.myenv.mydomain.com    128.234.33.198   80, 443   80m
```

## Get console credentials


You will need the credentials to access the various consoles installed by Verrazzano.

#### Consoles accessed by the same user name/password
- Grafana
- Prometheus
- Kibana
- Elasticsearch

**User:**  `verrazzano`

Run the following command to get the password:

`kubectl get secret --namespace verrazzano-system verrazzano -o jsonpath={.data.password} | base64 --decode; echo`


#### The Keycloak admin console

**User:** `keycloakadmin`

Run the following command to get the password:  

`kubectl get secret --namespace keycloak keycloak-http -o jsonpath={.data.password} | base64 --decode; echo`


#### The Rancher console

**User:** `admin`

Run the following command to get the password:  

`kubectl get secret --namespace cattle-system rancher-admin-secret -o jsonpath={.data.password} | base64 --decode; echo`


## (Optional) Install the example applications
Example applications are located in the `examples` directory.

## Uninstall Verrazzano

Run the following commands to delete a Verrazzano installation:

```
# Get the name of the Verrazzano custom resource
kubectl get verrazzano

# Delete the Verrazzano custom resource
kubectl delete verrazzano <name of custom resource>
```

Run the following command to monitor the console log of the uninstall:

```
kubectl logs -f $(kubectl get pod -l job-name=verrazzano-uninstall-my-verrazzano -o jsonpath="{.items[0].metadata.name}")
```

## Known Issues
#### OKE Missing Security List Ingress Rules

The install scripts perform a check, which attempts access through the ingress ports.  If the check fails, then the install will exit and you will see error messages like this:

`ERROR: Port 443 is NOT accessible on ingress(132.145.66.80)!  Check that security lists include an ingress rule for the node port 31739.`

On an OKE install, this may indicate that there is a missing ingress rule or rules.  To verify and fix the issue, do the following:
  1. Get the ports for the LoadBalancer services.
     * Run `kubectl get services -A`.
     * Note the ports for the LoadBalancer type services.  For example `80:31541/TCP,443:31739/TCP`.
  2. Check the security lists in the OCI Console.
     * Go to `Networking/Virtual Cloud Networks`.
     * Select the related VCN.
     * Go to the `Security Lists` for the VCN.
     * Select the security list named `oke-wkr-...`.
     * Check the ingress rules for the security list.  There should be one rule for each of the destination ports named in the LoadBalancer services.  In the above example, the destination ports are `31541` & `31739`. We would expect the ingress rule for `31739` to be missing because it was named in the ERROR output.
     * If a rule is missing, then add it by clicking `Add Ingress Rules` and filling in the source CIDR and destination port range (missing port).  Use the existing rules as a guide.

## Verrazzano Custom Resource Definition

The Verrazzano custom resource contains the configuration information for an installation.
Here a sample Verrazzano custom resource file that uses OCI DNS.  See other examples in
`./operator/config/samples`.

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  environmentName: env
  profile: prod
  components:
    certManager:
      certificate:
        acme:
          provider: letsEncrypt
          emailAddress: emailAddress@domain.com
    dns:
      oci:
        ociConfigSecret: ociConfigSecret
        dnsZoneCompartmentOCID: dnsZoneCompartmentOcid
        dnsZoneOCID: dnsZoneOcid
        dnsZoneName: my.dns.zone.name
    ingress:
      type: LoadBalancer

```

Following is a table that describes the `spec` portion of the Verrazzano custom resource:

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `environmentName` | string | Name of the installation.  This name is part of the endpoint access URLs that are generated. The default value is `default`. | No  
| `profile` | string | The installation profile to select.  Valid values are `prod` (production) and `dev` (development).  The default is `prod`. | No |
| `components` | [Components](#Components) | The Verrazzano Components.  | No  |


### Components
| Field | Type | Description | Required
| --- | --- | --- | --- |
| certManager | [CertManagerComponent](#certmanager-component) | The cert-manager component config.  | No | 
| dns | [DNSComponent](#dns-component) | The DNS component config.  | No | 
| ingress | [IngressComponent](#ingress-component) | The ingress component config. | No | 
| istio | [IstioComponent](#istio-component) | The Istio component config. | No | 

### CertManager Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| certificate | [Certificate](#certificate) | The certificate config. | No |

### Certificate
| Field | Type | Description | Required
| --- | --- | --- | --- |
| acme | [Acme](#acme) | The Acme config.  Either `acme` or `ca` must be specified. | No |
| ca | [CertificateAuthority](#CertificateAuthority) | The certificate authority config.  Either `acme` or `ca` must be specified. | No |

### Acme
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `provider` | string | Name of the Acme provider. |  Yes | 
| `emailAddress` | string | Email address of the user. |  Yes | 

### CertificateAuthority
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `secretName` | string | The secret name/ |  Yes | 
| `clusterResourceNamespace` | string | The secrete namespace. |  Yes | 

### DNS Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| oci | [DNS-OCI](#dns-oci) | OCI DNS config.  Either `oci` or `external` must be specified. | No |
| external | [DNS-External](#dns-external) | Extern DNS config. Either `oci` or `external` must be specified.   | No | 

### DNS OCI
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `ociConfigSecret` | string | Name of the OCI configuration secret.  Generate a secret named "oci-config" based on the OCI configuration profile you want to use.  You can specify a profile other than DEFAULT and a different secret name.  See instructions by running `./install/create_oci_config_secret.sh`.| Yes | 
| `dnsZoneCompartmentOCID` | string | The OCI DNS compartment OCID. |  Yes | 
| `dnsZoneOCID` | string | The OCI DNS zone OCID. |  Yes | 
| `dnsZoneName` | string | Name of OCI DNS zone. |  Yes | 

### DNS External
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `external.suffix` | string | The suffix for DNS names. |  Yes | 

### Ingress Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `type` | string | The ingress type.  Valid values are `LoadBalancer` and `NodePort`.  The default value is `LoadBalancer`.  |  Yes | 
| `ingressNginxArgs` |  [NameValue](#name-value) list | The list of arg names and values. | No |
| `ports` | [PortConfig](#port-config) list | The list port configs used by the ingress. | No |

### Port Config
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `name` | string | The port name.|  No | 
| `port` | string | The port value. |  Yes | 
| `targetPort` | string | The target port value. The default is same as port value. |  Yes | 
| `protocol` | string | The protocol used by the port.  TCP is default. |  No | 
| `nodePort` | string | The nodePort value. |  No | 
        
### Name Value
| Field | Type | Description | Required
| --- | --- | --- | --- |
| `name` | string | The arg name. |  Yes | 
| `value` | string | The arg value. Either `value` or `valueList` must be specifed. |  No | 
| `valueList` | string list | The list of arg values. Either `value` or `valueList` must be specifed.   |  No | 
| `setString` | boolean | Specifies if the value is a string |  No | 

### Istio Component
| Field | Type | Description | Required
| --- | --- | --- | --- |
| istioInstallArgs | [NameValue](#name-value) list | A list of Istio Helm chart arguments and values to apply during the installation of Istio.  Each argument is specified as either a `name/value` or `name/valueList` pair. | No |
