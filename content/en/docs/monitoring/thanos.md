---
title: "Thanos"
linkTitle: Thanos
description: "Learn how to use Thanos to monitor Verrazzano"
weight: 1
draft: false
---

Thanos is a group of components that seamlessly integrates with Prometheus to monitor your applications. You can install and configure Thanos components with Verrazzano and use long-term storage to store metrics. By using the Thanos console you can query for metrics across all Prometheus instances and long-term storage. Thanos also makes it easier to scale Prometheus horizontally and obtain a global view of data from multiple Prometheus servers.

Advantages of using Thanos:
- Long-term metrics retention
- High availability
- Easy backup for metrics
- Efficient data access

For more information on Thanos, see the [Thanos website](https://thanos.io/).

## Components

Thanos comprises of the following components:

| Components     | Description                                                                                                                                         |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| Sidecar        | Container that resides in the Prometheus pod. It connects to Prometheus, reads its data for queries, and uploads it to long-term storage.           |
| Store Gateway  | Serves metrics from long-term storage.                                                                                                              |
| Query          | Implements Prometheus API to aggregate data from the underlying components and provides a user interface for querying across all Prometheus stores. |
| Query Frontend | Implements Prometheus API and proxies it to Query while caching the response and optionally splits queries.                                        |

## Enable Thanos

You can enable the Thanos Prometheus Sidecar, Query, and Query Frontend components.

### Step 1: Create a YAML configuration file

Create an `objstore.yml` file using the OCI object storage.

{{< clipboard >}}
<div class="highlight">

```
type: OCI
config:
  provider: "raw"
  bucket: "<bucket_name>"
  compartment_ocid: "<stack_compartment_ocid>"
  tenancy_ocid: "<tenancy_ocid>"
  user_ocid: "<user_ocid>"
  region: "<region>"
  fingerprint: ""
  privatekey: ""
```

</div>
{{< /clipboard >}}

#### Step 2: Create a secret

Create the secret for object storage configuration.

The following example uses the filename `objstore.yml`. Using the `objstore.yml` filename helps you to generate the right key when creating the bucket secret.
The Store Gateway requires the secret key `objstore.yml` to fetch the bucket credentials.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl create namespace verrazzano-monitoring
$ kubectl create secret generic -n verrazzano-monitoring objstore-config --from-file objstore.yml
```

</div>
{{< /clipboard >}}

#### Step 3: Enable the Prometheus Thanos Sidecar, Thanos Query, and send metrics to long-term storage.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  components:
    prometheusOperator:
      enabled: true
      overrides:
      - values:
          prometheus:
            thanos
              integration: sidecar
            prometheusSpec:
              thanos:
                objectStorageConfig:
                  name: objstore-config
                  key: objstore.yml
    thanos:
      enabled: true
```

</div>
{{< /clipboard >}}

## Configure Thanos Store Gateway

Store Gateway helps you to query metrics in long-term storage.

Enable the `storegateway` with the following Verrazzano configuration, where `objstore-config` is an existing secret.

{{< clipboard >}}
<div class="highlight">

```
spec:
  components:
    ...
    ...
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

## Access Thanos Query Console

You can access the Thanos Query console using the instructions at [Get the consoles URLs]({{< relref "/docs/access/#get-the-consoles-urls" >}}). section in [Access Verrazzano]({{< relref "/docs/access/" >}}).
