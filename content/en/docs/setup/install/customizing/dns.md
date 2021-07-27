---
title: "Customizing DNS"
description: "Customize DNS configurations for Verrazzano system and application endpoints"
linkTitle: DNS
weight: 1
draft: true
---

This document describes how to customize DNS configurations with Verrazzano.

### Customizing DNS

Verrazzano supports 3 choices for DNS for Verrazzano services and applications:

* Free wildcard DNS services ([nip.io](https://nip.io/) and [sslip.io](https://sslip.io))
* [Oracle OCI DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/dnszonemanagement.htm) managed by Verrazzano
* Custom (user-managed) DNS

#### How Verrazzano Constructs the DNS Domain

Regardless of which DNS management you use with Verrazzano, the value in (`spec.environmentName`) will be used in 
conjunction with the configured domain in the `spec.components.dns` section of the custom resource to form 
the full domain name used to access Verrazzano ingresses.  

For example, if `us.v8o.example.com` is configured as the domain in `spec.components.dns`, you could use `sales` as an 
`environmentName`, yielding `sales.us.v8o.example.com` as the sales-related domain.


{{< tabs tabTotal="3" tabID="1" tabName1="Wildcard DNS" tabName2="OCI DNS" tabName3="Custom DNS">}}
{{< tab tabNum="1" >}}
<br>

#### Using Wildcard DNS

Verrazzano supports both the ([nip.io](https://nip.io/) and [sslip.io](https://sslip.io)) free wildcard DNS services.
Wildcard DNS services are services that, when queried with a hostname with an embedded IP address, returns that IP Address.

For example, using the [nip.io](https://nip.io/) service, the following DNS names all map to the IP address `10.0.0.1:

```
10.0.0.1.nip.io 
app.10.0.0.1.nip.io
customer1.app.10.0.0.1.nip.io
```

To configure Verrazzano to use one of these services, set the `spec.wildcard.domain` field in the Verrazzano
custom resource to either `nip.io` or `sslip.io`.  The default is `nip.io`.

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

#### Using OCI DNS

Verrazzano can directly manage records in [Oracle OCI DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/dnszonemanagement.htm) 
when configured to use the `spec.components.dns.oci` on behalf 

**Prerequisites**
* A DNS zone is a distinct portion of a domain namespace. Therefore, ensure that the zone is appropriately associated with a parent domain.
  For example, an appropriate zone name for parent domain `v8o.example.com` domain is `us.v8o.example.com`.
* Create a public OCI DNS zone using the OCI CLI or the OCI Console.

  To create an OCI DNS zone using the OCI CLI:
  ```
  $ oci dns zone create \
      -c <compartment ocid> \
      --name <zone-name-prefix>.v8o.example.com \
      --zone-type PRIMARY
  ```

  To create an OCI DNS zone using the OCI Console, see [Managing DNS Service Zones](https://docs.oracle.com/en-us/iaas/Content/DNS/Tasks/managingdnszones.htm).

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
      -s <config-file-section> \
      -k <secret-name>

  -o defaults to the OCI configuration file in ~/.oci/config
  -s defaults to the DEFAULT properties section within the OCI configuration file
  -k defaults to a secret named oci
  ```
  {{< alert title="NOTE" color="warning" >}}
  The `key_file` value within the OCI configuration file must reference a `.pem` file that contains a RSA private key.
  The contents of a RSA private key file starts with `-----BEGIN RSA PRIVATE KEY-----`.  If your OCI configuration file
  references a `.pem` file that is not of this form, then you must generate a RSA private key file.  See [Generating a RSA Private Key](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm).
  After generating the correct form of the `.pem` file, make sure to change the reference within the OCI configuration file.
  {{< /alert >}}

**Installation**

Installing Verrazzano using OCI DNS requires some configuration settings to create DNS records.

Download the sample Verrazzano custom resource `install-oci.yaml` for OCI DNS:
```
$ curl \
    -o ./install-oci.yaml \
    https://raw.githubusercontent.com/verrazzano/verrazzano/master/platform-operator/config/samples/install-oci.yaml
```

Edit the downloaded `install-oci.yaml` file and provide values for the following configuration settings:

* `spec.environmentName`
* `spec.components.dns.oci.ociConfigSecret`
* `spec.components.dns.oci.dnsZoneCompartmentOCID`
* `spec.components.dns.oci.dnsZoneOCID`
* `spec.components.dns.oci.dnsZoneName`

For the full configuration information for an installation, see the [Verrazzano Custom Resource Definition]({{< relref "/docs/reference/api/verrazzano/verrazzano.md" >}}).

When you use the OCI DNS installation, you need to provide a Verrazzano name in the Verrazzano custom resource
(`spec.environmentName`) that will be used as part of the domain name used to access Verrazzano
ingresses.  For example, you could use `sales` as an `environmentName`, yielding
`sales.us.v8o.example.com` as the sales-related domain (assuming the domain and zone names listed
previously).

For an example, a custom resource for a `prod` installation profile using OCI DNS might look as follows, yielding 
a domain of `myenv.example.mydomain.com`:

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
        dnsZoneName: example.mydomain.com
```

{{< /tab >}}
{{< tab tabNum="3" >}}
<br>

#### Install Using Custom/External DNS
<br>

Users can specify their own externally managed, custom DNS domain.  In this scenario, the user manages their own DNS 
domain and the management of all DNS records in that domain.

When using the `External` DNS type, the installer searches the DNS zone you provide for two specific A records.
These are used to configure the cluster and should refer to external addresses of the load balancers in the previous step.
The A records will need to be created manually.

{{< /tab >}}
{{< /tabs >}}
