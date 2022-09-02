---
title: Deprecated API Migration Guide
linkTitle: Deprecated API Migration Guide
weight: 100
draft: false
---

As the Verrazzano API evolves, APIs are periodically updated. When APIs evolve, the old API is deprecated and eventually removed.
This page contains information you need to know when migrating from deprecated API versions to newer and more stable API versions.

## Verrazzano

The install.verrazzano.io/v1alpha1 API version of Verrazzano resources is deprecated and will no longer be served in a future release.

- Migrate manifests and API clients to use the install.verrazzano.io/v1beta1 API version, available since 1.4.0.
- All existing persisted objects are accessible via the new API.

#### Notable Changes In install.verrazzano.io/v1beta1

- `spec.components.ingress` is renamed to `spec.components.ingressNGINX`.
- `spec.components.kibana` is renamed to `spec.components.opensearchDashboards`
- `spec.components.elasticsearch` is renamed to `spec.components.opensearch`
- `spec.components.fluentd.elasticsearchSecret` is renamed to `spec.components.fluentd.opensearchSecret`
- `spec.components.fluentd.elasticsearchURL` is renamed to `spec.components.fluentd.opensearchURL`
- `status.instance.kibanaUrl` is renamed to `status.instance.opensearchDashboardsUrl`
- `status.instance.elasticUrl` is renamed to `status.instance.opensearchUrl`
- use `spec.components.opensearch.nodes` instead of `spec.components.elasticsearch.installArgs`.
- use `spec.components.ingressNGINX.overrides` instead of `spec.components.ingress.nginxInstallArgs`.
- use `spec.components.istio.overrides` instead of `spec.components.istio.istioInstallArgs`.
- use `spec.components.istio.overrides` instead of `spec.components.istio.ingress`.
- use `spec.components.istio.overrides` instead of `spec.components.istio.egress`.
- use `spec.components.keycloak.overrides` instead of `spec.components.keycloak.keycloakInstallArgs`.
- use `spec.components.verrazzano.overrides` instead of `spec.components.verrazzano.installArgs`.
- use `spec.components.authProxy.overrides` instead of `spec.components.authProxy.kubernetes`.