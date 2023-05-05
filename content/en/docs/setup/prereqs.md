---
title: "Prerequisites"
description: "Review the prerequisite requirements, and the software versions installed and supported by Verrazzano"
weight: 1
draft: false
---


Verrazzano requires the following:
- A Kubernetes cluster and a compatible `kubectl`.
- `dev` profile - Each node in the cluster should contain at least two CPUs, 8 GB RAM, and 30 GB of disk storage. The entire cluster requires at least six CPUs, 48 GB RAM, and 100 GB of disk storage. In addition, about 52 GB of storage is required for the persistent volumes.
- `prod` profile - Each node in the cluster should contain at least two CPUs, 24 GB RAM, and 30 GB of disk storage. The entire cluster requires at least eight CPUs, 64 GB RAM, and 150 GB of disk storage. In addition, about 450 GB of storage is required for the persistent volumes.

The persistent volumes are provisioned using the default [StorageClass](https://kubernetes.io/docs/tasks/administer-cluster/change-default-storage-class/) in the cluster. In case of a  local disk based PV [provisioner](https://kubernetes.io/docs/concepts/storage/storage-classes/#provisioner), each node in the cluster should have a minimum of 80 GB of disk storage for both of the profiles.

{{< alert title="NOTE" color="warning" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster. Also, depending on the resource requirements of the applications you deploy, the configurations previously suggested may or may not be sufficient.
{{< /alert >}}

## Supported hardware
Verrazzano requires x86-64; other architectures are not supported.

## Supported software versions
Verrazzano supports the following software versions.

### Kubernetes
You can install Verrazzano on the following Kubernetes versions.

| Verrazzano | Release Date | Latest Patch Release | Latest Patch Release Date | End of Error Correction* | Kubernetes Versions    |
|------------|--------------|----------------------|---------------------------|--------------------------|------------------------|
| 1.5        | 2023-02-15   | 1.5.2                | 2023-03-17                | 2024-02-28**             | 1.21, 1.22, 1.23, 1.24 |
| 1.4        | 2022-09-30   | 1.4.4                | 2023-03-15                | 2023-10-31               | 1.21, 1.22, 1.23, 1.24 |
| 1.3        | 2022-05-24   | 1.3.8                | 2022-11-17                | 2023-05-31               | 1.21, 1.22, 1.23       |
| 1.2        | 2022-03-14   | 1.2.2                | 2022-05-10                | 2022-11-30               | 1.19, 1.20, 1.21       |
| 1.1        | 2021-12-16   | 1.1.2                | 2022-03-09                | 2022-09-30               | 1.19, 1.20, 1.21       |
| 1.0        | 2021-08-02   | 1.0.4                | 2021-12-20                | 2022-06-30               | 1.18, 1.19, 1.20       |

*_End of error correction for Verrazzano releases._<br>
**_Projected date. Actual date will be determined when the next minor or major release is available._

<br>

For more information, see [Kubernetes Release Documentation](https://kubernetes.io/releases/).
<br>For platform specific details, see [Verrazzano platform setup]({{< relref "/docs/setup/platforms/_index.md" >}}).

### WebLogic Server
The supported versions of WebLogic Server are dependent on the [WebLogic Kubernetes Operator](https://oracle.github.io/weblogic-kubernetes-operator/) version.
See the WebLogic Server versions supported [here](https://oracle.github.io/weblogic-kubernetes-operator/introduction/prerequisites/introduction/).


### Coherence
The supported versions of Coherence are dependent on the [Coherence Operator](https://oracle.github.io/coherence-operator/docs/latest/#/about/01_overview) version.
See the Coherence versions supported [here](https://oracle.github.io/coherence-operator/docs/latest/#/docs/installation/01_installation).

### Helidon
Verrazzano supports all versions of Helidon.  For more information, see [Helidon](https://helidon.io) and
 [Helidon Commercial Offerings](https://support.oracle.com/knowledge/Middleware/2645279_1.html).

## Installed software
Verrazzano installs a curated set of open source software. The following table lists each software, its  version, and a brief description.

  | Software       | Version    | Description                                                                 |
  |----------------|------------|-----------------------------------------------------------------------------|
  | Alertmanager   | 0.24.0   | Handles alerts sent by client applications, such as the Prometheus server.    |
  | Argo CD   | 2.5.3   | A declarative, GitOps continuous delivery tool for Kubernetes.                      |
  | cert-manager  | 1.9.1   | Automates the management and issuance of TLS certificates.                      |
  | Coherence Operator | 3.2.9   | Assists with deploying and managing Coherence clusters.                    |
  | [ExternalDNS](../../reference/api/vpo-verrazzano-v1alpha1/#install.verrazzano.io/v1alpha1.DNSComponent)    | 0.12.2   | Synchronizes exposed Kubernetes Services and ingresses with DNS providers.                       |
  | Fluentd   | 1.14.5   | Collects logs and sends them to OpenSearch.                                        |
  | Grafana   | 7.5.17   | Tool to help you examine, analyze, and monitor metrics.                            |
  | Istio   | 1.15.3   | Service mesh that layers transparently onto existing distributed applications.       |
  | Jaeger   | 1.42.0   | Distributed tracing system for monitoring and troubleshooting distributed systems.  |
  | Jaeger Operator   | 1.42.0   | Provides management for Jaeger tools.                                      |
  | Keycloak   | 20.0.1   | Provides single sign-on with Identity and Access Management.                      |
  | Kiali   | 1.57.1   | Management console for the Istio service mesh.                                       |
  | kube-state-metrics   | 2.6.0   | Provides metrics about the state of Kubernetes API objects.              |
  | MySQL   | 8.0.32   | Open source relational database management system used by Keycloak.                  |
  | MySQL Operator   | 8.0.32-2.0.8 |   Operator for managing MySQL InnoDB Cluster setups inside a Kubernetes cluster.    |
  | [NGINX Ingress Controller](../../reference/api/vpo-verrazzano-v1alpha1/#install.verrazzano.io/v1alpha1.IngressNginxComponent)   | 1.3.1   | Traffic management solution for cloud‑native applications in Kubernetes.                 |
  | Node Exporter  | 1.3.1   | Prometheus exporter for hardware and OS metrics.                               |
  | [OAM Kubernetes Runtime](../../reference/api/vpo-verrazzano-v1alpha1/#install.verrazzano.io/v1alpha1.OAMComponent)   | 0.3.3   | Plug-in for implementing the Open Application Model (OAM) control plane with Kubernetes. |
  | OpenSearch   | 2.3.0   | Provides a distributed, multitenant-capable full-text search engine.             |
  | OpenSearch Dashboards   | 2.3.0   | Provides search and data visualization capabilities for data indexed in OpenSearch. |
  | Prometheus   | 2.38.0   | Provides event monitoring and alerting.                                         |
  | Prometheus Adapter   | 0.10.0   | Provides metrics in support of pod autoscaling.                         |
  | Prometheus Operator   | 0.59.1  | Provides management for Prometheus monitoring tools.                    |
  | Prometheus Pushgateway   | 1.4.2   | Allows ephemeral and batch jobs to expose their metrics to Prometheus.   |
  | Rancher   | 2.6.8   | Manages multiple Kubernetes clusters.                                               |
  | Rancher Backup Operator   | 2.1.3   | Manages backup and restore of Rancher configurations and data.      |
  | Velero   | 1.9.1   | Manages backup and restore of Kubernetes configurations and data.                    |
  | [WebLogic Kubernetes Operator](../../reference/api/vpo-verrazzano-v1alpha1/#install.verrazzano.io/v1alpha1.WebLogicOperatorComponent)   | 4.0.6   | Assists with deploying and managing WebLogic domains.                                    |
  | [WebLogic Monitoring Exporter](../../reference/api/vpo-verrazzano-v1alpha1/#install.verrazzano.io/v1alpha1.WebLogicOperatorComponent)   | 2.1.3   | Exports Prometheus-compatible metrics from WebLogic instances.                           |
