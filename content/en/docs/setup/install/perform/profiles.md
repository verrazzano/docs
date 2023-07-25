---
title: "Installation Profiles"
weight: 2
draft: false
aliases:
- /docs/setup/install/profiles
---

This document describes built-in configuration profiles that you can use to simplify a Verrazzano installation.  An installation
profile is a well-known configuration of Verrazzano settings that can be referenced by name, which then can be
customized as needed.

The following table describes the Verrazzano installation profiles.

| Profile           | Description                                                                 | Characteristics                                                                                                                                                                                 |
|-------------------|:----------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `prod`            | Full installation, production configuration.                                | Default profile:<br/>- Full installation.<br/>- Persistent storage. <br/>- Production OpenSearch cluster topology.                                                                              |
| `dev`             | Development or evaluation configuration.                                    | Lightweight installation:<br/>- For evaluation purposes.<br/>- No persistence.<br/>- Single-node OpenSearch cluster topology.                                                                   |
| `managed-cluster` | A specialized installation for managed clusters in a multicluster topology. | Minimal installation for a managed cluster:<br/>- Clusters must be registered with an admin cluster to use [multicluster]({{< relref "/docs/introduction/verrazzanomulticluster" >}}) features. |

## Use an installation profile

To specify an installation profile when installing Verrazzano, set the profile name in the `profile` field of your
Verrazzano custom resource.

For example, to use the `dev` profile:
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: example-verrazzano
spec:
  profile: dev
```

</div>
{{< /clipboard >}}

To use a different profile, replace `dev` with `prod`, or `managed-cluster`.

## Customize an installation profile

Regardless of the profile, you can override the profile settings for any component. The following example
uses a customized `dev` profile to configure a small 8 Gi persistent volume for the MySQL instance used by Keycloak to
provide more stability for the Keycloak service.
{{< clipboard >}}
<div class="highlight">

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

</div>
{{< /clipboard >}}

For details on how to customize Verrazzano components, see [Modify Verrazzano Installations]({{< relref "/docs/setup/modify-installation.md" >}}).

## Profile configurations

The following table lists the Verrazzano components that are enabled by default with each profile.  Note that you can
customize any Verrazzano installation regardless of the profile.

| Component                   | dev | prod | managed-cluster |
|-----------------------------|:---:|:----:|:---------------:|
| `applicationOperator`       | ✔️  |  ✔️  |       ✔️        |
| `argoCD`                    |     |      |                 |
| `authProxy`                 | ✔️  |  ✔️  |       ✔️        |
| `certManager`               | ✔️  |  ✔️  |       ✔️        |
| `certManagerWebhookOCI`     |  ️  |  ️   |                 |
| `clusterAPI`                | ✔️  |  ✔️  |                 |
| `clusterAgent`              | ✔️  |  ✔️  |       ✔️        |
| `clusterIssuer`             | ✔️  |  ✔️  |       ✔️        |
| `clusterOperator`           | ✔️  |  ✔️  |       ✔️        |
| `coherenceOperator`         | ✔️  |  ✔️  |       ✔️        |
| `console`                   | ✔️  |  ✔️  |                 |
| `dns`                       | ✔️  |  ✔️  |       ✔️        |
| `fluentbitOpensearchOutput` |     |      |                 |
| `fluentd`                   | ✔️  |  ✔️  |       ✔️        |
| `fluentOperator`            |  ️  |  ️   |        ️        |
| `grafana`                   | ✔️  |  ✔️  |                 |
| `ingressNGINX`              | ✔️  |  ✔️  |       ✔️        |
| `istio`                     | ✔️  |  ✔️  |       ✔️        |
| `jaegerOperator`            |     |      |                 |
| `keycloak`                  | ✔️  |  ✔️  |                 |
| `kiali`                     | ✔️  |  ✔️  |                 |
| `kubeStateMetrics`          |     |      |                 |
| `mySQLOperator`             | ✔️  |  ✔️  |       ✔️        |
| `oam`                       | ✔️  |  ✔️  |       ✔️        |
| `opensearch`                | ✔️  |  ✔️  |                 |
| `opensearchDashboards`      | ✔️  |  ✔️  |                 |
| `prometheus`                | ✔️  |  ✔️  |       ✔️        |
| `prometheusAdapter`         |     |      |                 |
| `prometheusNodeExporter`    | ✔️  |  ✔️  |       ✔️        |
| `prometheusOperator`        | ✔️  |  ✔️  |       ✔️        |
| `prometheusPushgateway`     |     |      |                 |
| `rancher`                   | ✔️  |  ✔️  |                 |
| `rancherBackup`             |     |      |                 |
| `thanos`                    |     |      |                 |
| `velero`                    |     |      |                 |
| `weblogicOperator`          | ✔️  |  ✔️  |       ✔️        |

### Prometheus and Grafana configurations

The following table describes the Prometheus and Grafana configurations in each profile.

| Profile           | Prometheus                                     | Grafana                                       |
|-------------------|:-----------------------------------------------|:----------------------------------------------|
| `prod`            | One replica (128 MB memory, 50 Gi storage)     | One replica (48 MB memory, 50 Gi storage)     |
| `dev`             | One replica (128 MB memory, ephemeral storage) | One replica (48 MB memory, ephemeral storage) |
| `managed-cluster` | One replica (128 MB memory, 50 Gi storage)     | Not installed                                 |

### OpenSearch Dashboards and OpenSearch configurations

The following table describes the OpenSearch Dashboards and OpenSearch cluster topology in each profile.

| Profile           | OpenSearch                                                                                                                                                               | OpenSearch Dashboards                          |
|-------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------|
| `prod`            | Three master replicas (1.4 Gi memory, 50 Gi storage each)<br/>One ingest replica (2.5 Gi memory, no storage)<br/>Three data replicas (4.8 Gi memory, 50 Gi storage each) | One replica (192 MB memory, ephemeral storage) |
| `dev`             | One master/data/ingest replica (1 Gi memory, ephemeral storage)                                                                                                          | One replica (192 MB memory, ephemeral storage) |
| `managed-cluster` | Not installed                                                                                                                                                            | Not installed                                  |

{{< alert title="NOTE" color="primary" >}}
OpenSearch containers are configured to use 75% of the configured request memory for the Java min/max heap settings.
{{< /alert >}}


### Profile-independent defaults

The following table shows the settings for components that are profile-independent (consistent across
all profiles unless overridden).

| Component    | Default                                                                                                                                                                            |
|--------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| DNS          | Wildcard DNS provider [nip.io](https://nip.io).                                                                                                                                    |
| Certificates | Uses the [cert-manager](https://cert-manager.io/) self-signed [ClusterIssuer](https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.ClusterIssuer) for certificates. |
| Ingress-type | Defaults to `LoadBalancer` service type for the ingress.                                                                                                                           |
