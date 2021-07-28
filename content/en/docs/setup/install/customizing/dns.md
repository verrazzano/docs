---
title: "Customize DNS"
description: "Customize DNS configurations for Verrazzano system and application endpoints"
linkTitle: DNS
weight: 1
draft: false
---

### Customizing DNS

Verrazzano supports 3 choices for DNS for Verrazzano services and applications:

* Free wildcard DNS services ([nip.io](https://nip.io/) and [sslip.io](https://sslip.io))
* [Oracle OCI DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/dnszonemanagement.htm) managed by Verrazzano
* Custom (user-managed) DNS

#### How Verrazzano Constructs a DNS Domain

Regardless of which DNS management you use with Verrazzano, the value in 
[`spec.environmentName`](/docs/reference/api/verrazzano/verrazzano/#verrazzanospec) field in your installed will be used in 
conjunction with the configured domain in the [`spec.components.dns`](/docs/reference/api/verrazzano/verrazzano/#dns-component) 
section of the custom resource to form the full domain name used to access Verrazzano ingresses.  

For example, if `us.mydomain.com` is configured as the domain in `spec.components.dns`, you could use `sales` as an 
`environmentName`, yielding `sales.us.mydomain.com` as the sales-related domain.


{{< tabs tabTotal="3" tabID="1" tabName1="Wildcard DNS" tabName2="OCI DNS" tabName3="Custom DNS">}}
{{< tab tabNum="1" >}}
<br>

Verrazzano supports both the ([nip.io](https://nip.io/) and [sslip.io](https://sslip.io)) free wildcard DNS services.
Wildcard DNS services are services that, when queried with a hostname with an embedded IP address, returns that IP Address.

For example, using the [nip.io](https://nip.io/) service, the following DNS names all map to the IP address `10.0.0.1`:

```
10.0.0.1.nip.io 
app.10.0.0.1.nip.io
customer1.app.10.0.0.1.nip.io
```

To configure Verrazzano to use one of these services, simply set the 
[`spec.wildcard.domain`](/docs/reference/api/verrazzano/verrazzano#dns-wildcard) 
field in the Verrazzano custom resource to either `nip.io` or `sslip.io`.  The default is `nip.io`.

For example, the following configuration uses `sslip.io` instead of `nip.io` for wildcard DNS with a `dev` installation profile:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  profile: dev
  environmentName: default
  components:
    dns:
      wildcard:
        domain: sslip.io
```
<br/>

{{< /tab >}}
{{< tab tabNum="2" >}}
<br>

Verrazzano can directly manage records in [Oracle OCI DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/dnszonemanagement.htm) 
when configured to use the [`spec.components.dns.oci`](/docs/reference/api/verrazzano/verrazzano#dns-oci).  This is achieved
through the [External DNS Service](https://github.com/kubernetes-sigs/external-dns), which is a component that is 
conditionally installed when OCI DNS is configured for DNS management in Verrazzano.

**Prerequisites**
* A DNS zone is a distinct portion of a domain namespace. Therefore, ensure that the zone is appropriately associated with a parent domain.
  For example, an appropriate zone name for parent domain `mydomain.com` domain is `us.mydomain.com`.
* Create a public OCI DNS zone using the OCI CLI or the OCI Console.

  To create an OCI DNS zone using the OCI CLI:
  ```
  $ oci dns zone create \
      -c <compartment ocid> \
      --name <zone-name-prefix>.mydomain.com \
      --zone-type PRIMARY
  ```

  To create an OCI DNS zone using the OCI Console, see 
  [Managing DNS Service Zones](https://docs.oracle.com/en-us/iaas/Content/DNS/Tasks/managingdnszones.htm).

* Create a secret in the default namespace. The secret is created using the script `create_oci_config_secret.sh` which
  reads an OCI configuration file to create the secret.

  Download the `create_oci_config_secret.sh` script:
  ```
  $ curl \
      -o ./create_oci_config_secret.sh \
      https://raw.githubusercontent.com/verrazzano/verrazzano/master/platform-operator/scripts/install/create_oci_config_secret.sh
  ```

  Run the `create_oci_config_secret.sh` script:
  ```
  $ chmod +x create_oci_config_secret.sh
  $ export KUBECONFIG=<kubeconfig-file>
  $ ./create_oci_config_secret.sh \
      -o <oci-config-file> \
      -s <oci-config-file-profile> \
      -k <secret-name>

  -o defaults to the OCI configuration file in ~/.oci/config
  -s defaults to the DEFAULT properties section within the OCI configuration file
  -k defaults to a secret named oci
  ```
  {{< alert title="NOTE" color="warning" >}}
  The `key_file` value within the OCI configuration file must reference a `.pem` file that contains a RSA private key.
  The contents of a RSA private key file starts with `-----BEGIN RSA PRIVATE KEY-----`.  If your OCI configuration file
  references a `.pem` file that is not of this form, then you must generate a RSA private key file.  See 
  [Generating a RSA Private Key](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm).
  After generating the correct form of the `.pem` file, make sure to change the reference within the OCI configuration file.
  {{< /alert >}}

**Configuration**

Configuring Verrazzano to use OCI DNS requires some configuration settings to create DNS records.

Download the sample Verrazzano custom resource `install-oci.yaml` for OCI DNS:
```
$ curl \
    -o ./install-oci.yaml \
    https://raw.githubusercontent.com/verrazzano/verrazzano/master/platform-operator/config/samples/install-oci.yaml
```

Edit the downloaded `install-oci.yaml` file and provide values for the following configuration settings in the
custom resource spec:

* [`spec.environmentName`](/docs/reference/api/verrazzano/verrazzano/#verrazzanospec)
* `spec.components.dns.oci.ociConfigSecret`
* `spec.components.dns.oci.dnsZoneCompartmentOCID`
* `spec.components.dns.oci.dnsZoneOCID`
* `spec.components.dns.oci.dnsZoneName`


See [`spec.components.dns.oci`](/docs/reference/api/verrazzano/verrazzano#dns-oci) for details on the OCI DNS 
configuration settings.

For example, a custom resource for a `prod` installation profile using OCI DNS might look as follows, yielding 
a domain of `myenv.mydomain.com` (OCI identifiers redacted):

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  profile: prod
  environmentName: myenv
  components:
    dns:
      oci:
        ociConfigSecret: oci
        dnsZoneCompartmentOCID: ocid1.compartment.oc1..compartment-ocid
        dnsZoneOCID: ocid1.dns-zone.oc1..zone-ocid
        dnsZoneName: mydomain.com
```

{{< /tab >}}
{{< tab tabNum="3" >}}
<br>

Users can specify their own externally managed, custom DNS domain.  In this scenario, the user manages their own DNS 
domain and the management of all DNS records in that domain.

An externally managed DNS domain is specified in the [`spec.components.dns.external.suffix`](/docs/reference/api/verrazzano/verrazzano/#dns-external) 
field of the Verrazzano custom resource.  

When using an externally managed DNS domain, the responsibility lies with the user for

* Configuring A records for Verrazzano ingress points (load balancers)
* Configuring CNAME records for hostnames in the domain that point to the A records as needed

The Verrazzano installer searches the DNS zone you provide for two specific A records.  
These are used to configure the cluster and should refer to external addresses of the load balancers provisioned by
the user.

The A records will need to be created manually.

|Record             | Use                                                                                              |
|-------------------|--------------------------------------------------------------------------------------------------|
|`ingress-mgmt`       | Set as the `.spec.externalIPs` value of the `ingress-controller-nginx-ingress-controller` service. |
|`ingress-verrazzano` | Set as the `.spec.externalIPs` value of the `istio-ingressgateway` service.                       |

For example, if `spec.environmentName` is set to `myenv`, and `spec.components.dns.external.suffix` is
set to `mydomain.com`, the A records would need to be set up as follows:

```
198.51.100.10                                   A       ingress-mgmt.myenv.mydomain.com.
203.0.113.10                                    A       ingress-verrazzano.myenv.mydomain.com.
```

This example assumes that load balancers exist for `ingress-mgmt` on `198.51.100.10` and for `ingress-verrazzano` on
`203.0.113.10`.

For a more complete example, see the documentation for setting up Verrazzano on the 
[OLCNE Platform](/docs/setup/platforms/olcne/olcne/).
{{< /tab >}}
{{< /tabs >}}
