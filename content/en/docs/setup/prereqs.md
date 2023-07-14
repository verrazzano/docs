---
title: "Prerequisites"
description: "Review the prerequisite requirements, and the software versions installed and supported by Verrazzano"
weight: 1
draft: false
---


Verrazzano requires the following:
- A Kubernetes cluster and a compatible `kubectl`.
- `dev` profile - At least two CPUs, 100 GB disk storage, and 16 GB RAM available on the Kubernetes worker nodes. Depending on the resource requirements of the applications you deploy, this may or may not be sufficient.
- `prod` profile - At least four CPUs, 100 GB disk storage, and 32 GB RAM available on the Kubernetes worker nodes.  Depending on the resource requirements of the applications you deploy, this may or may not be sufficient.

{{< alert title="NOTE" color="warning" >}}
To avoid conflicts with Verrazzano system components, we recommend installing Verrazzano into an empty cluster.
{{< /alert >}}

## Supported hardware
Verrazzano requires x86-64; other architectures are not supported.

## Supported software versions
Verrazzano supports the following software versions.

### Kubernetes
You can install Verrazzano on the following Kubernetes versions.

| Verrazzano | End of Error Correction*|
|------------|-------------------------|
| 1.4        | 2023-10-31              |
| 1.3        | 2023-05-31              |
| 1.2        | 2022-11-30              |
| 1.1        | 2022-09-30              |
| 1.0        | 2022-06-30              |

*_End of error correction for Verrazzano releases._<br>

<br>

For more information, see [Kubernetes Release Documentation](https://kubernetes.io/releases/).
For platform specific details, see [Verrazzano platform setup]({{< relref "/docs/setup/platforms/_index.md" >}}).

### WebLogic Server
The supported versions of WebLogic Server are dependent on the [WebLogic Kubernetes Operator](https://oracle.github.io/weblogic-kubernetes-operator/) version.
See the WebLogic Server versions supported [here](https://oracle.github.io/weblogic-kubernetes-operator/introduction/prerequisites/introduction/).


### Coherence
The supported versions of Coherence are dependent on the [Coherence Operator](https://oracle.github.io/coherence-operator/docs/latest/#/about/01_overview) version.
See the Coherence versions supported [here](https://oracle.github.io/coherence-operator/docs/latest/#/docs/installation/01_installation).

### Helidon
Verrazzano supports all versions of Helidon.  For more information, see [Helidon](https://helidon.io) and
 [Helidon Commercial Offerings](https://support.oracle.com/knowledge/Middleware/2645279_1.html).

## Installed components
Verrazzano installs a curated set of open source components.  The following table lists each
component, its version, and a brief description.

| Component                    | Version | Description                                                                              |
|------------------------------|---------|------------------------------------------------------------------------------------------|
| alert-manager                | 0.24.0  | Handles alerts sent by client applications, such as the Prometheus server.               |
| cert-manager                 | 1.7.1   | Automates the management and issuance of TLS certificates.                               |
| Coherence Operator           | 3.2.9   | Assists with deploying and managing Coherence clusters.                                  |
| ExternalDNS                  | 0.10.2  | Synchronizes exposed Kubernetes Services and ingresses with DNS providers.               |
| Fluentd                      | 1.14.5  | Collects logs and sends them to OpenSearch.                                              |
| Grafana                      | 7.5.17  | Tool to help you examine, analyze, and monitor metrics.                                  |
| Istio                        | 1.14.3  | Service mesh that layers transparently onto existing distributed applications.           |
| Jaeger                       | 1.34.1  | Distributed tracing system for monitoring and troubleshooting distributed systems.       |
| Jaeger Operator              | 1.34.1  | Provides management for Jaeger tools.                                                    |
| Keycloak                     | 15.0.2  | Provides single sign-on with Identity and Access Management.                             |
| Kiali                        | 1.42.0  | Management console for the Istio service mesh.                                           |
| kube-state-metrics           | 2.4.2   | Provides metrics about the state of Kubernetes API objects.                              |
| MySQL                        | 8.0.29  | Open source relational database management system used by Keycloak.                      |
| NGINX Ingress Controller     | 1.1.1   | Traffic management solution for cloud‑native applications in Kubernetes.                 |
| Node Exporter                | 1.3.1   | Prometheus exporter for hardware and OS metrics.                                         |
| OAM Kubernetes Runtime       | 0.3.0   | Plug-in for implementing the Open Application Model (OAM) control plane with Kubernetes. |
| OpenSearch                   | 1.2.3   | Provides a distributed, multitenant-capable full-text search engine.                     |
| OpenSearch Dashboards        | 1.2.0   | Provides search and data visualization capabilities for data indexed in OpenSearch.      |
| Prometheus                   | 2.34.0  | Provides event monitoring and alerting.                                                  |
| Prometheus Adapter           | 0.9.1   | Provides metrics in support of pod autoscaling.                                          |
| Prometheus Operator          | 0.55.1  | Provides management for Prometheus monitoring tools.                                     |
| Prometheus Pushgateway       | 1.4.2   | Allows ephemeral and batch jobs to expose their metrics to Prometheus.                   |
| Rancher                      | 2.6.8   | Manages multiple Kubernetes clusters.                                                    |
| Rancher Backup Operator      | 2.1.3   | Manages backup and restore of Rancher configurations and data.                           |
| Velero                       | 1.9.1   | Manages backup and restore of Kubernetes configurations and data.                        |
| WebLogic Kubernetes Operator | 3.4.7   | Assists with deploying and managing WebLogic domains.                                    |
| WebLogic Monitoring Exporter | 2.1.3   | Exports Prometheus-compatible metrics from WebLogic instances.                           |
