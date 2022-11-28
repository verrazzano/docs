---
title: "Installation Profiles"
description: "How to use named Verrazzano configurations to simplify an installation"
weight: 2
draft: false
---

This document describes built-in configuration profiles that you can use to simplify a Verrazzano installation.  An installation
profile is a well-known configuration of Verrazzano settings that can be referenced by name, which then can be
customized as needed.

The following table describes the Verrazzano installation profiles.

| Profile  | Description | Characteristics
| ------------- |:------------- |:-------------
| `prod` | Full installation, production configuration. | Default profile:<br/>- Full installation.<br/>- Persistent storage. <br/>- Production OpenSearch cluster topology.
| `dev` | Development or evaluation configuration. | Lightweight installation:<br/>- For evaluation purposes.<br/>- No persistence.<br/>- Single-node OpenSearch cluster topology.
| `managed-cluster` | A specialized installation for managed clusters in a multicluster topology. | Minimal installation for a managed cluster:<br/>- Cluster must be registered with an admin cluster to use [multicluster]({{< relref "/docs/concepts/verrazzanomulticluster" >}}) features.

## Use an installation profile

To specify an installation profile when installing Verrazzano, set the profile name in the `profile` field of your
Verrazzano custom resource.

For example, to use the `dev` profile:

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
```

To use a different profile, replace `dev` with `prod` or `managed-cluster`.

## Customize an installation profile

You can override the profile settings for any component regardless of the profile.  The following example
uses a customized `dev` profile to configure a small 8Gi persistent volume for the MySQL instance used by Keycloak to
provide more stability for the Keycloak service.

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: custom-dev-example
spec:
  profile: dev
  components:
    keycloak:
      mysql:
        volumeSource:
          persistentVolumeClaim:
            claimName: mysql
  volumeClaimSpecTemplates:
  - metadata:
      name: mysql      
    spec:
      resources:
        requests:
          storage: 8Gi
```

For details on how to customize Verrazzano components, see [Customize an Installation]({{< relref "/docs/customize" >}}).

## Profile configurations

The following table lists the Verrazzano components that are installed with each profile.  Note that you can
customize any Verrazzano installation, regardless of the profile.

| Component               | dev | prod | managed-cluster |
|-------------------------|:---:|:----:|:---------------:|
| applicationOperator:    | ✔️  |  ✔️  |       ✔️        |
| authProxy:              | ✔️  |  ✔️  |       ✔️        |
| certManager:            | ✔️  |  ✔️  |       ✔️        |
| coherenceOperator:      | ✔️  |  ✔️  |       ✔️        |
| console:                | ✔️  |  ✔️  |       ✔️        |
| dns:                    | ✔️  |  ✔️  |       ✔️        |
| fluentd:                | ✔️  |  ✔️  |       ✔️        |
| grafana:                | ✔️  |  ✔️  |       ✔️        |
| ingressNGINX:           | ✔️  |  ✔️  |       ✔️        |
| istio:                  | ✔️  |  ✔️  |       ✔️        |
| jaegerOperator:         | ✔️  |  ✔️  |       ✔️        |
| keycloak:               | ✔️  |  ✔️  |       ✔️        |
| kiali:                  | ✔️  |  ✔️  |       ✔️        |
| kubeStateMetrics:       | ✔️  |  ✔️  |       ✔️        |
| mySQLOperator:          | ✔️  |  ✔️  |       ✔️        |
| oam:                    | ✔️  |  ✔️  |       ✔️        |
| opensearch:             | ✔️  |  ✔️  |       ✔️        |
| opensearchDashboards:   | ✔️  |  ✔️  |       ✔️        |
| prometheus:             | ✔️  |  ✔️  |       ✔️        |
| prometheusAdapter:      | ✔️  |  ✔️  |       ✔️        |
| prometheusNodeExporter: | ✔️  |  ✔️  |       ✔️        |
| prometheusOperator:     | ✔️  |  ✔️  |       ✔️        |
| prometheusPushgateway:  | ✔️  |  ✔️  |       ✔️        |
| rancher:                | ✔️  |  ✔️  |       ✔️        |
| rancherBackup:          | ✔️  |  ✔️  |       ✔️        |
| velero:                 | ✔️  |  ✔️  |       ✔️        |
| weblogicOperator:       | ✔️  |  ✔️  |       ✔️        |

### Prometheus and Grafana configurations

The following table describes the Prometheus and Grafana configurations in each profile.

| Profile | Prometheus | Grafana
| ------------- |:------------- |:-------------
| `prod` | 1 replica (128M memory, 50Gi storage) | 1 replica (48M memory, 50Gi storage)
| `dev` | 1 replica (128M memory, ephemeral storage) | 1 replica (48M memory, ephemeral storage)
| `managed-cluster` | 1 replica (128M memory, 50Gi storage) | Not installed

### OpenSearch Dashboards and OpenSearch configurations

The following table describes the OpenSearch Dashboards and OpenSearch cluster topology in each profile.

| Profile | OpenSearch                                                                                                                                                | OpenSearch Dashboards
| ------------- |:----------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------
| `prod` | 3 master replicas (1.4Gi memory, 50Gi storage each)<br/>1 ingest replica (2.5Gi memory, no storage)<br/>3 data replicas (4.8Gi memory, 50Gi storage each) | 1 replica (192M memory, ephemeral storage)
| `dev` | 1 master/data/ingest replica (1Gi memory, ephemeral storage)                                                                                              | 1 replica (192M memory, ephemeral storage)
| `managed-cluster` | Not installed                                                                                                                                             | Not installed

{{< alert title="NOTE" color="warning" >}}
OpenSearch containers are configured to use 75% of the configured request memory for the Java min/max heap settings.
{{< /alert >}}


### Profile-independent defaults

The following table shows the settings for components that are profile-independent (consistent across
all profiles unless overridden).

| Component | Default
| -------------|-------------
| DNS |  Wildcard DNS provider [nip.io](https://nip.io).
| Certificates | Uses the [cert-manager](https://cert-manager.io/) self-signed [ClusterIssuer](https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.ClusterIssuer) for certificates.
| Ingress-type | Defaults to `LoadBalancer` service type for the ingress.

For details on how to customize Verrazzano components, see [Customize an Installation]({{< relref "/docs/customize" >}}).
