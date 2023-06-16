---
title: "Thanos"
linkTitle: Thanos
description: "Use Thanos to access and store metrics data"
weight: 3
draft: false
---

Thanos is a group of components that seamlessly integrate with Prometheus to monitor your applications. You can enable and configure Thanos components with Verrazzano and use long-term storage to store metrics. By using the Thanos console, you can query for metrics across all Prometheus instances and long-term storage. Thanos also makes it easier to scale Prometheus horizontally and obtain a global view of data from multiple Prometheus servers.

Advantages of using Thanos:
- Long-term metrics retention
- High availability
- Easy backup for metrics
- Efficient data access

For more information on Thanos, see the [Thanos website](https://thanos.io/).

## Thanos components

Verrazzano currently supports the following Thanos components:

| Components     | Description                                                                                                                                         |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| Sidecar        | Container that resides in the Prometheus pod. It connects to Prometheus, reads its data for queries, and uploads it to long-term storage.           |
| Store Gateway  | Serves metrics from long-term storage.                                                                                                              |
| Query          | Implements Prometheus API to aggregate data from the underlying components and provides a user interface for querying across all Prometheus stores. |
| Query Frontend | Implements Prometheus API and proxies it to Query while caching the response and optionally splits queries.                                        |

## Enable Thanos

To enable Thanos in Verrazzano, add the following:

{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  components:
    prometheusOperator:
      enabled: true
      overrides:
      - values:
          prometheus:
            thanos:
              integration: sidecar
    thanos:
      enabled: true
```

</div>
{{< /clipboard >}}

## Enable long-term storage using OCI Object Storage

Optionally, you can configure Thanos to use [OCI Object Storage](https://docs.oracle.com/en-us/iaas/Content/Object/Concepts/objectstorageoverview.htm) 
for long-term storage of metrics.

To enable this behavior complete the following steps:

### Step 1: Create a YAML configuration file

Create a local file named `storage.yaml` that identifies your OCI Object Storage bucket name, the region and compartment
where it is located within your OCI tenancy, and a valid set of credentials for Thanos to use when accessing it.

{{< clipboard >}}
<div class="highlight">

```
type: OCI
config:
  provider: "raw"
  bucket: "thanos"
  compartment_ocid: "ocid1.compartment.oc1....."
  region: "us-ashburn-1"
  tenancy_ocid: "ocid1.tenancy.oc1....."
  user_ocid: "ocid1.user.oc1....."
  fingerprint: "12:d3:4c:..."
  key: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
```

</div>
{{< /clipboard >}}

### Step 2: Create a secret

Create the secret for object storage configuration using the `storage.yaml` file you created in Step 1.

The Thanos Store Gateway requires the key in the secret to be `objstore.yml`.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl create namespace verrazzano-monitoring
$ kubectl create secret generic objstore-config -n verrazzano-monitoring --from-file=objstore.yml=storage.yaml
```

</div>
{{< /clipboard >}}

### Step 3: Enable storage and Thanos Store Gateway

The following example enables storage, creates the required secret, and enables Thanos Store Gateway in the Verrazzano 
custom resource. It also configures the Thanos Sidecar to write to object storage and the Store Gateway to read from 
object storage.

**Note**: `objstore-config` is the secret that you created in Step 2.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  components:
    prometheusOperator:
      enabled: true
      overrides:
      - values:
          prometheus:
            thanos:
              integration: sidecar
            prometheusSpec:
              thanos:
                objectStorageConfig:
                  name: objstore-config
                  key: objstore.yml
    thanos:
      enabled: true
      overrides:
      - values:
          existingObjstoreSecret: objstore-config
          storegateway:
            enabled: true
```

</div>
{{< /clipboard >}}

## Access the Thanos Query console

You can access the Thanos Query console using the instructions at [Get the consoles URLs]({{< relref "/docs/setup/access/#get-the-consoles-urls" >}}).
