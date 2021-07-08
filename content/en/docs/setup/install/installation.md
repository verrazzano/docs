---
title: "Install Guide"
description: "How to install Verrazzano"
weight: 1
draft: false
---

{{< alert title="NOTE" color="warning" >}}
You should install this developer preview release of Verrazzano only in a cluster that can be safely deleted when your evaluation is complete.
{{< /alert >}}

The following instructions show you how to install Verrazzano in a
single Kubernetes cluster.

## Prerequisites

Verrazzano requires the following:
- A Kubernetes cluster and a compatible `kubectl`.
- At least 2 CPUs, 100GB disk storage, and 16GB RAM available on the Kubernetes worker nodes.  This is sufficient to install the development profile
  of Verrazzano.  Depending on the resource requirements of the applications you deploy, this may or may not be sufficient for deploying your
  applications.

For a list of the open source components and versions installed with Verrazzano, see [Software Versions]({{< relref "/docs/reference/versions.md" >}}).

{{< alert title="NOTE" color="warning" >}}
Verrazzano has been tested _only_ on the following versions of Kubernetes: 1.17.x, 1.18.x, 1.19.x, and 1.20x.  Other versions have not been tested and are not guaranteed to work.
{{< /alert >}}


## Prepare for the install

Before installing Verrazzano, see instructions on preparing the following Kubernetes platforms:

* [OCI Container Engine for Kubernetes]({{< relref "/docs/setup/platforms/oci/oci.md" >}})

* [OLCNE]({{< relref "/docs/setup/platforms/olcne/olcne.md" >}})

* [KIND]({{< relref "/docs/setup/platforms/kind/kind.md" >}})

* [minikube]({{< relref "/docs/setup/platforms/minikube/minikube.md" >}})

* [Generic Kubernetes]({{< relref "/docs/setup/platforms/generic/generic.md" >}})

**NOTE**: Verrazzano can create network policies that can be used to limit the ports and protocols that pods use for network communication. Network policies provide additional security but they are enforced only if you install a Kubernetes Container Network Interface (CNI) plug-in that enforces them, such as Calico. For instructions on how to install a CNI plug-in, see the documentation for your Kubernetes cluster.

## Install the Verrazzano platform operator

Verrazzano provides a platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to manage the life cycle of Verrazzano installations.  Through the [Verrazzano]({{< relref "/docs/reference/api/verrazzano/verrazzano.md" >}})
custom resource you can install, uninstall, and upgrade Verrazzano installations.

To install the Verrazzano platform operator:

1. Deploy the Verrazzano platform operator.

    ```shell
    $ kubectl apply -f https://github.com/verrazzano/verrazzano/releases/latest/download/operator.yaml
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

Verrazzano supports the following installation profiles:  development (`dev`), production (`prod`), and
managed cluster (`managed-cluster`).  See the [Installation Profiles]({{< relref "/docs/setup/install/profiles.md"  >}}) document for more details.

To change profiles in any of the following commands, set the `VZ_PROFILE` environment variable to the name of the profile you want to install.

{{< alert title="NOTE" color="warning" >}}
For Verrazzano installations on the minikube platform, use only the development profile.
{{< /alert >}}

For a complete description of Verrazzano configuration options, see the [Verrazzano Custom Resource Definition]({{< relref "/docs/reference/api/verrazzano/verrazzano.md" >}}).

According to your DNS choice, [nip.io](https://nip.io/) (wildcard DNS) or
[Oracle OCI DNS](https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Concepts/dnszonemanagement.htm),
install Verrazzano using one of the following methods:

{{< tabs tabTotal="2" tabID="2" tabName1="nip.io" tabName2="OCI DNS" >}}
{{< tab tabNum="1" >}}
<br>

#### Install using nip.io

Run the following commands:

```shell
$ kubectl apply -f - <<EOF
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  profile: ${VZ_PROFILE:-dev}
EOF
$ kubectl wait --timeout=20m --for=condition=InstallComplete verrazzano/my-verrazzano
```

{{< /tab >}}
{{< tab tabNum="2" >}}
<br>

#### Install using OCI DNS

**Prerequisites**
* A DNS zone is a distinct portion of a domain namespace. Therefore, ensure that the zone is appropriately associated with a parent domain.
For example, an appropriate zone name for parent domain `v8o.example.com` domain is `us.v8o.example.com`.
* Create a public OCI DNS zone using the OCI CLI or the OCI Console.

  To create an OCI DNS zone using the OCI CLI:
  ```
  $ oci dns zone create -c <compartment ocid> --name <zone-name-prefix>.v8o.example.com --zone-type PRIMARY
  ```

  To create an OCI DNS zone using the OCI console, see [Managing DNS Service Zones](https://docs.oracle.com/en-us/iaas/Content/DNS/Tasks/managingdnszones.htm).

* Create a secret in the default namespace. The secret is created using the script `create_oci_config_secret.sh` which
reads an OCI configuration file to create the secret.

  Download the `create_oci_config_secret.sh` script:
  ```
  $ curl -o ./create_oci_config_secret.sh https://raw.githubusercontent.com/verrazzano/verrazzano/master/platform-operator/scripts/install/create_oci_config_secret.sh
  ```

  Run the `create_oci_config_secret.sh` script:
  ```
  $ chmod +x create_oci_config_secret.sh
  $ export KUBECONFIG=<kubeconfig-file>
  $ ./create_oci_config_secret.sh -o <oci-config-file> -s <config-file-section> -k <secret-name>

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
$ curl -o ./install-oci.yaml https://raw.githubusercontent.com/verrazzano/verrazzano/master/platform-operator/config/samples/install-oci.yaml
```

Edit the downloaded `install-oci.yaml` file and provide values for the following configuration settings:

* `spec.environmentName`
* `spec.certificate.acme.emailAddress`
* `spec.dns.oci.ociConfigSecret`
* `spec.dns.oci.dnsZoneCompartmentOCID`
* `spec.dns.oci.dnsZoneOCID`
* `spec.dns.oci.dnsZoneName`

For the full configuration information for an installation, see the [Verrazzano Custom Resource Definition]({{< relref "/docs/reference/api/verrazzano/verrazzano.md" >}}).

When you use the OCI DNS installation, you need to provide a Verrazzano name in the Verrazzano custom resource
 (`spec.environmentName`) that will be used as part of the domain name used to access Verrazzano
ingresses.  For example, you could use `sales` as an `environmentName`, yielding
`sales.us.v8o.example.com` as the sales-related domain (assuming the domain and zone names listed
previously).

Run the following commands:

```
$ kubectl apply -f ./install-oci.yaml
$ kubectl wait --timeout=20m --for=condition=InstallComplete verrazzano/my-verrazzano
```

{{< /tab >}}
{{< /tabs >}}


To monitor the console log output of the installation:
```shell
$ kubectl logs -f $(kubectl get pod -l job-name=verrazzano-install-my-verrazzano -o jsonpath="{.items[0].metadata.name}")
```

## Verify the install

Verrazzano installs multiple objects in multiple namespaces. In the `verrazzano-system` namespaces, all the pods in the `Running` state, does not guarantee, but likely indicates that Verrazzano is up and running.
```
$ kubectl get pods -n verrazzano-system
coherence-operator-controller-manager-7557bc4c49-7w55p   1/1     Running   0          27h
fluentd-fzmsl                                            1/1     Running   0          27h
fluentd-r9wwf                                            1/1     Running   0          27h
fluentd-zp2r2                                            1/1     Running   0          27h
oam-kubernetes-runtime-6ff589f66f-r95qv                  1/1     Running   0          27h
verrazzano-api-669c7d7f66-rcnl8                          1/1     Running   0          27h
verrazzano-application-operator-b5b77d676-7w95p          1/1     Running   0          27h
verrazzano-console-6b469dff9c-b2jwk                      1/1     Running   0          27h
verrazzano-monitoring-operator-54cb658774-f6jjm          1/1     Running   0          27h
verrazzano-operator-7f4b99d7d-wg7qm                      1/1     Running   0          27h
vmi-system-es-master-0                                   2/2     Running   0          27h
vmi-system-grafana-74bb7cdf65-k97pb                      2/2     Running   0          27h
vmi-system-kibana-85565975b5-7hfdf                       2/2     Running   0          27h
vmi-system-prometheus-0-7bf464d898-czq8r                 4/4     Running   0          27h
weblogic-operator-7db5cdcf59-qxsr9                       1/1     Running   0          27h
```

## (Optional) Run the example applications
Example applications are located [here]({{< relref "/docs/samples/_index.md" >}}).

##### To get the consoles URLs and credentials, see [Access Verrazzano]({{< relref "/docs/operations/_index.md" >}}).
