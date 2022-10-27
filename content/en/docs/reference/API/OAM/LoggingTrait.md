---
title: LoggingTrait
weight: 2
draft: false
---

#### LoggingTrait

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | LoggingTrait | Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. | No |
| `spec` |  [LoggingTraitSpec](#loggingtraitspec) | The desired state of a logging trait. | Yes |

#### LoggingTraitSpec
LoggingTraitSpec specifies the desired state of a logging trait.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `loggingConfig` | string | A string representation of the Fluentd configuration. | Yes |
| `loggingImage` | string | The name of the custom Fluentd image. | Yes |