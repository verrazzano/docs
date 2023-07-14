---
title: "Prerequisites"
description: "Review the prerequisite requirements, software versions installed and supported by Verrazzano"
weight: 1
draft: false
---


Verrazzano requires the following:
- A Kubernetes cluster and a compatible `kubectl`.
- At least 2 CPUs, 100GB disk storage, and 16GB RAM available on the Kubernetes worker nodes.  This is sufficient to install the development profile
  of Verrazzano.  Depending on the resource requirements of the applications you deploy, this may or may not be sufficient for deploying your
  applications.

## Supported Hardware
Verrazzano requires x86-64; other architectures are not supported.

## Supported Software Versions
Verrazzano supports the following software versions.

### Kubernetes
You can install Verrazzano on the following Kubernetes versions.

| Verrazzano | Kubernetes Versions |
|------------|---------------------|
| 1.0        | 1.18, 1.19, 1.20    |
| 1.1        | 1.19, 1.20, 1.21    |
| 1.2        | 1.19, 1.20, 1.21    |

For more information, see [Kubernetes Release Documentation](https://kubernetes.io/releases/).
For platform specific details, see [Verrazzano platform setup]({{< relref "/docs/setup/platforms/_index.md" >}}).

### WebLogic Server
The supported versions of WebLogic Server are dependent on the [WebLogic Kubernetes Operator](https://oracle.github.io/weblogic-kubernetes-operator/) version.
See the WebLogic Server versions supported [here](https://oracle.github.io/weblogic-kubernetes-operator/userguide/prerequisites/introduction/).


### Coherence
The supported versions of Coherence are dependent on the [Coherence Operator](https://oracle.github.io/coherence-operator/docs/latest/#/about/01_overview) version.
See the Coherence versions supported [here](https://oracle.github.io/coherence-operator/docs/latest/#/docs/installation/01_installation).

### Helidon
Verrazzano supports all versions of Helidon.  For more information, see [Helidon](https://helidon.io) and
 [Helidon Commercial Offerings](https://support.oracle.com/knowledge/Middleware/2645279_1.html).

## Installed Components
Verrazzano installs a curated set of open source components.  The following table lists each open source
component with its version and a brief description.

| Component                    | Version | Description                                                                          |
|------------------------------|---------|--------------------------------------------------------------------------------------|
| cert-manager                 | 1.2.0   | Automates the management and issuance of TLS certificates.                           |
| Coherence Operator           | 3.2.3   | Assists with deploying and managing Coherence clusters.                              |
| OpenSearch                   | 1.2.3   | Provides a distributed, multitenant-capable full-text search engine.                 |
| ExternalDNS                  | 0.10.2  | Synchronizes exposed Kubernetes Services and ingresses with DNS providers.           |
| Fluentd                      | 1.12.3  | Collects logs and sends them to OpenSearch.                                          |
| Grafana                      | 7.5.11  | Tool to help you study, analyze, and monitor metrics.                                |
| Istio                        | 1.10.4  | Service mesh that layers transparently onto existing distributed applications.       |
| Keycloak                     | 15.0.2  | Provides single sign-on with Identity and Access Management.                         |
| Kiali                        | 1.34.1  | Management console for the Istio service mesh.                                       |
| OpenSearch Dashboards        | 1.2.0   | Provides search and data visualization capabilities for data indexed in OpenSearch.  |
| MySQL                        | 8.0.28  | Open source relational database management system used by Keycloak.                  |
| NGINX Ingress Controller     | 0.46.0  | Traffic management solution for cloud‑native applications in Kubernetes.             |
| Node Exporter                | 1.0.0   | Prometheus exporter for hardware and OS metrics.                                     |
| OAM Kubernetes Runtime       | 0.3.0   | Plug-in for implementing Open Application Model (OAM) control plane with Kubernetes. |
| Prometheus                   | 2.31.1  | Provides event monitoring and alerting.                                              |
| Rancher                      | 2.5.9   | Manages multiple Kubernetes clusters.                                                |
| WebLogic Kubernetes Operator | 3.3.7   | Assists with deploying and managing WebLogic domains.                                |
