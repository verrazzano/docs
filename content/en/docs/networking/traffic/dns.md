---
title: "Customize DNS"
description: "Customize DNS configurations for Verrazzano system and application endpoints"
weight: 2
draft: false
aliases:
  - /docs/customize/dns
  - /docs/networking/traffic/dns
---

Verrazzano supports three DNS choices for Verrazzano services and applications:

* Free [wildcard DNS services](#wildcard-dns-services) ([nip.io](https://nip.io/) and [sslip.io](https://sslip.io))
* [Oracle Cloud Infrastructure DNS](#oracle-cloud-infrastructure-dns) managed by Verrazzano
* [Custom](#custom-dns) (user-managed) DNS

## How Verrazzano constructs a DNS domain

Regardless of which DNS management you use, the value in the
[`spec.environmentName`](/docs/reference/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.VerrazzanoSpec) field in your installation will be
prepended to the configured domain in the [`spec.components.dns`](/docs/reference/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.DNSComponent)
section of the custom resource, to form the full DNS domain name used to access Verrazzano endpoints.  

For example, if `spec.environmentName` is set to `sales` and the domain is configured in `spec.components.dns` as `us.example.com`,
Verrazzano will create `sales.us.example.com` as the DNS domain for the installation.

### Wildcard DNS Services

Verrazzano can be configured to use either the [nip.io](https://nip.io/) or [sslip.io](https://sslip.io) free wildcard DNS services.
When queried with a host name with an embedded IP address, wildcard DNS services return that IP address.

For example, using the `nip.io` service, the following DNS names all map to the IP address `10.0.0.1`:
{{< clipboard >}}
<div class="highlight">

```
10.0.0.1.nip.io
app.10.0.0.1.nip.io
customer1.app.10.0.0.1.nip.io
```
</div>
{{< /clipboard >}}

To configure Verrazzano to use one of these services, set the
[`spec.wildcard.domain`](/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.Wildcard)
field in the Verrazzano custom resource to either `nip.io` or `sslip.io`; the default is `nip.io`.

For example, the following configuration uses `sslip.io`, instead of `nip.io`, for wildcard DNS with a `dev` installation profile.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
  components:
    dns:
      wildcard:
        domain: sslip.io
```
</div>
{{< /clipboard >}}


### Oracle Cloud Infrastructure DNS


Verrazzano can directly manage records in [Oracle Oracle Cloud Infrastructure DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/dnszonemanagement.htm)
when configured to use the [`spec.components.dns.oci`](/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.OCI) field.  This is achieved
through the [External DNS Service](https://github.com/kubernetes-sigs/external-dns), which is a component that is
conditionally installed when Oracle Cloud Infrastructure DNS is configured for DNS management in Verrazzano.

#### Prerequisites

The following prerequisites must be met before using Oracle Cloud Infrastructure DNS with Verrazzano:

* You must have control of a DNS domain.
* You must have an Oracle Cloud Infrastructure DNS Service Zone that is configured to manage records for that domain. Verrazzano also supports the use of both GLOBAL and PRIVATE Oracle Cloud Infrastructure DNS zones.

  A DNS Service Zone is a distinct portion of a domain namespace. You must ensure that the zone is appropriately associated with a parent domain.
  For example, an appropriate zone name for parent domain `example.com` is `us.example.com`.

  To create an Oracle Cloud Infrastructure DNS zone using the Oracle Cloud Infrastructure CLI:
  {{< clipboard >}}
  <div class="highlight">

  ```
  $ oci dns zone create \
      -c <compartment ocid> \
      --name <zone-name-prefix>.example.com \
      --zone-type PRIMARY
  ```
  </div>
  {{< /clipboard >}}
  To create an Oracle Cloud Infrastructure DNS zone using the Oracle Cloud Infrastructure Console, see
  [Managing DNS Service Zones](https://docs.oracle.com/en-us/iaas/Content/DNS/Tasks/managingdnszones.htm).

* You must have a valid Oracle Cloud Infrastructure API signing key that can be used to communicate with Oracle Cloud Infrastructure DNS in your tenancy.  

  For example, you can create an API signing key using the Oracle Cloud Infrastructure CLI.
  {{< clipboard >}}
  <div class="highlight">

  ```
    $ oci setup keys --key-name myapikey
    Enter a passphrase for your private key (empty for no passphrase):
    Public key written to: /Users/jdoe/.oci/myapikey_public.pem
    Private key written to: /Users/jdoe/.oci/myapikey.pem
    Public key fingerprint: 39:08:44:69:9f:f5:73:86:7a:46:d8:ad:34:4f:95:29

  ```
   </div>
  {{< /clipboard >}}
  If you haven't already uploaded your API signing public key through the
  console, follow the instructions in this section, [How to upload the public key](https://docs.cloud.oracle.com/Content/API/Concepts/apisigningkey.htm#How2).

  After the key pair has been created, you must upload the public key to your account in your Oracle Cloud Infrastructure tenancy.   For details, see
  the Oracle Cloud Infrastructure documentation, [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm).

#### Create an Oracle Cloud Infrastructure API secret in the target cluster

To communicate with Oracle Cloud Infrastructure DNS to manage DNS records, Verrazzano needs to be made aware of the necessary API credentials.  
A generic Kubernetes secret must be created in the cluster's `verrazzano-install` namespace with the required credentials.
That secret must then be referenced by the custom resource that is used to install Verrazzano.  

After you have an Oracle Cloud Infrastructure API key ready for use, create a YAML file, `oci.yaml`, with the API credentials in the form:
{{< clipboard >}}
<div class="highlight">

```
auth:
  region: <oci-region>
  tenancy: <oci-tenancy-ocid>
  user: <oci-user-ocid>
  key: |
    <oci-api-private-key-file-contents>
  fingerprint: <oci-api-private-key-fingerprint>
```
</div>
{{< /clipboard >}}

This information typically can be found in your Oracle Cloud Infrastructure CLI config file or in the Oracle Cloud Infrastructure Console.  The
`<oci-api-private-key-file-contents>` contents are the PEM-encoded contents of the `key_file` value within the Oracle Cloud Infrastructure CLI
configuration profile.

For example, your `oci.yaml` file will look similar to the following:
{{< clipboard >}}
<div class="highlight">

```
auth:
  region: us-ashburn-1
  tenancy: ocid1.tenancy.oc1.....
  user: ocid1.user.oc1.....
  key: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
  fingerprint: 12:d3:4c:gh:fd:9e:27:g8:b9:0d:9f:00:22:33:c3:gg
```
</div>
{{< /clipboard >}}

Verrazzano also supports the use of instance principals to communicate with Oracle Cloud Infrastructure in order to create or update Oracle Cloud Infrastructure DNS records.
Instance principals require some prerequisites that can be found [here](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/callingservicesfrominstances.htm).

When using instance principals, your `oci.yaml` file will look as follows:
{{< clipboard >}}
<div class="highlight">

```
auth:
  authtype: instance_principal
```
</div>
{{< /clipboard >}}

Then, you can create a generic Kubernetes secret in the cluster's `verrazzano-install` namespace using `kubectl`.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl create secret generic -n verrazzano-install <secret-name> --from-file=<path-to-oci-yaml-file>
```
</div>
{{< /clipboard >}}

For example, to create a secret named `oci` from a file `oci.yaml`, do the following:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl create secret generic -n verrazzano-install oci --from-file=oci.yaml
```
</div>
{{< /clipboard >}}

This secret will later be referenced from the Verrazzano custom resource used during installation.

#### Use a Verrazzano helper script to create an Oracle Cloud Infrastructure secret

Verrazzano also provides a helper script to create the necessary Kubernetes secret based on your Oracle Cloud Infrastructure CLI configuration file,
assuming that you have the Oracle Cloud Infrastructure CLI installed and a valid Oracle Cloud Infrastructure CLI profile with the required API key information. The script
`create_oci_config_secret.sh` reads your Oracle Cloud Infrastructure CLI configuration file to create the secret.

First, download the `create_oci_config_secret.sh` script.
{{< clipboard >}}
<div class="highlight">

```
$ curl \
    -o ./create_oci_config_secret.sh \
    {{< release_source_url raw=true path="platform-operator/scripts/install/create_oci_config_secret.sh" >}}
```
</div>
{{< /clipboard >}}

Next, set your `KUBECONFIG` environment variable to point to your cluster and run `create_oci_config_secret.sh -h`
to display the script options.
{{< clipboard >}}
<div class="highlight">

```
$ chmod +x create_oci_config_secret.sh
$ export KUBECONFIG=<kubeconfig-file>
$ ./create_oci_config_secret.sh  -h
usage: ./create_oci_config_secret.sh [-o oci_config_file] [-s config_file_section]
  -o oci_config_file         The full path to the Oracle Cloud Infrastructure configuration file (default ~/.oci/config)
  -s config_file_section     The properties section within the Oracle Cloud Infrastructure configuration file.  Default is DEFAULT
  -k secret_name             The secret name containing the Oracle Cloud Infrastructure configuration.  Default is oci
  -c context_name            The kubectl context to use
  -a auth_type               The auth_type to be used to access Oracle Cloud Infrastructure. Valid values are user_principal/instance_principal. Default is user_principal.
  -h                         Help
```
</div>
{{< /clipboard >}}

For example, to have the script create the YAML file using your `[DEFAULT]` Oracle Cloud Infrastructure CLI profile and then create a Kubernetes secret
named `oci`, you can run the script with no arguments, as follows:
{{< clipboard >}}
<div class="highlight">

```
$ ./create_oci_config_secret.sh
secret/oci created
```
</div>
{{< /clipboard >}}


The following example creates a secret `myoci` using an Oracle Cloud Infrastructure CLI profile named `[dev]`.
{{< clipboard >}}
<div class="highlight">

```
$ ./create_oci_config_secret.sh -s dev -k myoci
secret/myoci created
```
</div>
{{< /clipboard >}}

When using instance principals, all other parameters will be ignored automatically. The following example creates a secret `myoci` using Oracle Cloud Infrastructure instance principal.
{{< clipboard >}}
<div class="highlight">

```
$ ./create_oci_config_secret.sh -a instance_principal
secret/myoci created
```
</div>
{{< /clipboard >}}


#### Installation

After the Oracle Cloud Infrastructure API secret is created, create a Verrazzano custom resource for the installation that is configured to use Oracle Cloud Infrastructure
DNS and reference the secret you created.

As a starting point, download the sample Verrazzano custom resource `install-oci.yaml` file for Oracle Cloud Infrastructure DNS.
{{< clipboard >}}
<div class="highlight">

```
$ curl \
    -o ./install-oci.yaml \
    {{< release_source_url raw=true path="platform-operator/config/samples/install-oci.yaml" >}}
```
</div>
{{< /clipboard >}}

Edit the `install-oci.yaml` file to provide values for the following configuration settings in the
custom resource spec:

* [`spec.environmentName`](/docs/reference/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.VerrazzanoSpec)
* `spec.components.dns.oci.ociConfigSecret`
* `spec.components.dns.oci.dnsZoneCompartmentOCID`
* `spec.components.dns.oci.dnsZoneOCID`
* `spec.components.dns.oci.dnsZoneName`
* `spec.components.dns.oci.dnsScope`

The field `spec.components.dns.oci.ociConfigSecret` should reference the secret created earlier. For details on the
Oracle Cloud Infrastructure DNS configuration settings, see [`spec.components.dns.oci`](/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.OCI).

For example, a custom resource for a `prod` installation profile using Oracle Cloud Infrastructure DNS might look as follows, yielding
a domain of `myenv.example.com` (Oracle Cloud Infrastructure identifiers redacted):
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: prod
  environmentName: myenv
  components:
    dns:
      oci:
        ociConfigSecret: oci
        dnsZoneCompartmentOCID: ocid1.compartment.oc1..compartment-ocid
        dnsZoneOCID: ocid1.dns-zone.oc1..zone-ocid
        dnsZoneName: example.com
```
</div>
{{< /clipboard >}}

If using a private DNS zone, then the same `prod` installation profile using Oracle Cloud Infrastructure DNS will look as follows:
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
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
        dnsZoneName: example.com
        dnsScope: PRIVATE
```
</div>
{{< /clipboard >}}

After the custom resource is ready, apply it using `kubectl apply -f <path-to-custom-resource-file>`.

### Custom DNS

You can specify your own externally managed, custom DNS domain.  In this scenario, you manage your own DNS
domain and all DNS records in that domain.

An externally managed DNS domain is specified in the [`spec.components.dns.external.suffix`](/docs/reference/vpo-verrazzano-v1beta1/#install.verrazzano.io/v1beta1.External)
field of the Verrazzano custom resource.  

When using an externally managed DNS domain, you are responsible for:

* Configuring A records for Verrazzano ingress points (load balancers)
* Configuring CNAME records for host names in the domain that point to the A records, as needed

The Verrazzano installer searches the DNS zone you provide for two specific A records.  
These are used to configure the cluster and should refer to external addresses of the load balancers provisioned by
the user.

The A records need to be created manually.

|Record             | Use                                                                                              |
|-------------------|--------------------------------------------------------------------------------------------------|
|`ingress-mgmt`       | Set as the `.spec.externalIPs` value of the `ingress-controller-nginx-ingress-controller` service. |
|`ingress-verrazzano` | Set as the `.spec.externalIPs` value of the `istio-ingressgateway` service.                       |

For example, if `spec.environmentName` is set to `myenv`, and `spec.components.dns.external.suffix` is
set to `example.com`, the A records would need to be set up as follows:
{{< clipboard >}}
<div class="highlight">

```
198.51.100.10                                   A       ingress-mgmt.myenv.example.com.
203.0.113.10                                    A       ingress-verrazzano.myenv.example.com.
```
</div>
{{< /clipboard >}}

This example assumes that load balancers exist for `ingress-mgmt` on `198.51.100.10` and for `ingress-verrazzano` on
`203.0.113.10`.

For a more complete example, see the documentation for setting up Verrazzano on the
[Oracle Cloud Native Environment Platform]({{< relref "/docs/setup/install/prepare/platforms/olcne/_index.md" >}}).
