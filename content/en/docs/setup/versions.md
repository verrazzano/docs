---
title: "Software Versions"
description: "Review the software versions installed and supported by Verrazzano"
weight: 1
draft: false
---


## Supported Software Versions
Verrazzano supports the following software versions.

### Kubernetes
You can install Verrazzano on the following Kubernetes versions.

| Verrazzano | Release Date | Latest Patch Release | Latest Patch Release Date | Kubernetes Versions
| ---        |--------------| ---                  | ---                       | ---
| 1.0        | 2021-08-02   | 1.0.4                | 2021-11-06                | 1.18, 1.19, 1.20
| 1.1        | 2021-12-16   |                      |                           | 1.19, 1.20, 1.21

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

| Component | Version  | Description |
| ---       |----------| ---         |
| cert-manager | 1.2.0    | Automates the management and issuance of TLS certificates.
| Coherence Operator | 3.2.3    | Assists with deploying and managing Coherence clusters.
| Elasticsearch | 7.10.2   | Provides a distributed, multitenant-capable full-text search engine.
| ExternalDNS | 0.7.1    | Synchronizes exposed Kubernetes Services and ingresses with DNS providers.
| Fluentd | 1.12.3   | Collects logs and sends them to Elasticsearch.
| Grafana | 7.2.1-2  | Tool to help you study, analyze, and monitor metrics.
| Istio | 1.10.4   | Service mesh that layers transparently onto existing distributed applications.
| Keycloak | 15.0.2   | Provides single sign-on with Identity and Access Management.
| Kiali | 1.34.1   | Management console for the Istio service mesh.
| Kibana | 7.10.2   | Provides search and data visualization capabilities for data indexed in Elasticsearch.
| MySQL | 8.0.26   | Open source relational database management system used by Keycloak.
| NGINX Ingress Controller | 0.46.0   | Traffic management solution for cloud‑native applications in Kubernetes.
| Node Exporter | 1.0.0    | Prometheus exporter for hardware and OS metrics.
| OAM Kubernetes Runtime | 0.3.0    | Plug-in for implementing Open Application Model (OAM) control plane with Kubernetes.
| Prometheus | 2.21.0-1 | Provides event monitoring and alerting.
| Rancher | 2.5.9    | Manages multiple Kubernetes clusters.
| WebLogic Kubernetes Operator | 3.3.6    | Assists with deploying and managing WebLogic domains.
