---
title: MetricsTrait
weight: 2
draft: false
---

#### MetricsTrait

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | MetricsTrait |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` |  [MetricsTraitSpec](#metricstraitspec) | The desired state of a metrics trait. |  Yes |

#### MetricsTraitSpec
MetricsTraitSpec specifies the desired state of a metrics trait.

| Field | Type | Description                                                                                                                                                      | Required
| --- | --- |------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| `port` | integer | The HTTP port for the related metrics endpoint. Defaults to `8080`.                                                                                              | No |
| `path` | string | The HTTP path for the related metrics endpoint. Defaults to `/metrics`.                                                                                          | No |
| `secret` | string | The name of an opaque secret (for example, user name and password) within the workload’s namespace for metrics endpoint access.                                  | No |
| `scraper` | string | The Prometheus deployment used to scrape the related metrics endpoints. By default, the Verrazzano-supplied Prometheus component is used to scrape the endpoint. | No |
