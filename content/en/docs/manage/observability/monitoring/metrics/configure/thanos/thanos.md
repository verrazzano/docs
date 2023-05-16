---
title: "Thanos"
linkTitle: Thanos
description: "Learn how to use Thanos to monitor Verrazzano"
weight: 2
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

## Enable long-term storage

Optionally, to enable long-term storage of metrics complete the following steps:

### Step 1: Create a YAML configuration file

Create a `storage.yaml` file using OCI object storage.

{{< clipboard >}}
<div class="highlight">

```
type: OCI
config:
  provider: "raw"
  bucket: "<bucket name>"
  compartment_ocid: "<bucket compartment OCID>"
  tenancy_ocid: "<tenancy OCID>"
  user_ocid: "<user OCID>"
  region: "<region>"
  fingerprint: ""
  privatekey: ""
```

</div>
{{< /clipboard >}}

### Step 2: Create a secret

Create the secret for object storage configuration.

The following example uses the file name `storage.yaml`. The Thanos Store Gateway requires the key in the secret to be `objstore.yml`.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl create namespace verrazzano-monitoring
$ kubectl create secret generic objstore-config -n verrazzano-monitoring --from-file=objstore.yml=storage.yaml
```

</div>
{{< /clipboard >}}

### Step 3: Enable storage and Thanos Store Gateway

The following example enables storage, creates the required secret, and enables Thanos Store Gateway. It also configures the Thanos Sidecar to write to object storage and the Store Gateway to read from object storage.

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

You can access the Thanos Query console using the instructions at [Get the consoles URLs]({{< relref "/docs/access/#get-the-consoles-urls" >}}).
