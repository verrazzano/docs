---
title: Deprecated API Migration Guide
linkTitle: Deprecated API Migration Guide
weight: 100
draft: false
---

As the Verrazzano API evolves, APIs are periodically updated. When APIs evolve, the old API is deprecated and eventually removed.
This document contains information that you need to know when migrating from deprecated API versions to newer and more stable API versions.

## Verrazzano

The `install.verrazzano.io/v1alpha1` API version of Verrazzano resources is deprecated and will no longer be served in a future release.

- Migrate manifests and API clients to use the `install.verrazzano.io/v1beta1` API version, available since 1.4.0.
- All existing persisted objects are accessible using the new API.

#### Notable Changes In `install.verrazzano.io/v1beta1`

- `spec.components.ingress` is renamed to `spec.components.ingressNGINX`.
- `spec.components.kibana` is renamed to `spec.components.opensearchDashboards`
- `spec.components.elasticsearch` is renamed to `spec.components.opensearch`
- `spec.components.fluentd.elasticsearchSecret` is renamed to `spec.components.fluentd.opensearchSecret`
- `spec.components.fluentd.elasticsearchURL` is renamed to `spec.components.fluentd.opensearchURL`
- `status.instance.kibanaUrl` is renamed to `status.instance.opensearchDashboardsUrl`
- `status.instance.elasticUrl` is renamed to `status.instance.opensearchUrl`
- Use `spec.components.opensearch.nodes` instead of `spec.components.elasticsearch.installArgs`.
- Use `spec.components.ingressNGINX.overrides` instead of `spec.components.ingress.nginxInstallArgs`.
- Use `spec.components.istio.overrides` instead of `spec.components.istio.istioInstallArgs`.
- Use `spec.components.istio.overrides` instead of `spec.components.istio.ingress`.
- Use `spec.components.istio.overrides` instead of `spec.components.istio.egress`.
- Use `spec.components.keycloak.overrides` instead of `spec.components.keycloak.keycloakInstallArgs`.
- Use `spec.components.verrazzano.overrides` instead of `spec.components.verrazzano.installArgs`.
- Use `spec.components.authProxy.overrides` instead of `spec.components.authProxy.kubernetes`.

#### Co-installing previous Verrazzano versions

After installing Verrazzano version 1.4.0 or later, and not uninstalling it _before_ installing versions of Verrazzano prior to 1.4.0, will result in the following error:

```
The CustomResourceDefinition "verrazzanos.install.verrazzano.io" is invalid: status.storedVersions[0]: Invalid value: "v1beta1": must appear in spec.versions
```

To resolve this error, delete the `verrazzanos.install.verrazzano.io` Custom Resource Definition:

```shell
$ kubectl delete customresourcedefinition verrazzanos.install.verrazzano.io
```

## Multicluster

Some of the multicluster wrappers APIs, which are part of `clusters.verrazzano.io/v1alpha1`, are deprecated and will be removed in Verrazzano v2.0.0.
The APIs that will be removed are:

- MultiClusterComponent - Should be replaced with a `core.oam/dev/v1alpha2` Component resource.
- MultiClusterConfigMap - Should be replaced with a `core.oam/dev/v1alpha2` Component resource.
- MultiClusterSecret - Should be replaced with a Kubernetes Secret and referenced in the `spec.secrets` of a MultiClusterApplicationConfiguration resource.
