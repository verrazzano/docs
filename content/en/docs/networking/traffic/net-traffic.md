---
title: "Network Traffic"
linkTitle: "Network Traffic"
description: "Verrazzano Network Traffic"
weight: 3
draft: true
---

The following table shows all of the pod ports that allow ingress into
Verrazzano components.

| Component  | Pod Port           | From  | Description |
| ------------- |:------------- |:------------- |:----- |:-------------:|
| Verrazzano Application Operator | 9443 | Kubernetes API Server  | Webhook entrypoint 
| Verrazzano Platform Operator | 9443 | Kubernetes API Server  | Webhook entrypoint 
| Verrazzano Console | 8000 | NGINX Ingress |  Access from external client  
| Verrazzano Console | 15090 | Prometheus | Prometheus scraping
| Verrazzano Proxy | 8775 | NGINX Ingress |  Access from external client 
| Verrazzano Proxy | 15090 | Prometheus | Prometheus scraping
| cert-manager| 9402 | Prometheus | Prometheus scraping
| Coherence Operator | 9443 | Prometheus | Webhook entrypoint 
| Elasticsearch | 8775 | NGINX Ingress | Access from external client  
| Elasticsearch | 8775 | Fluentd | Access from Fluentd 
| Elasticsearch | 9200 | Kibana, Internal | Elasticsearch data port  
| Elasticsearch | 9300 | Internal | Elasticsearch cluster port  
| Elasticsearch | 15090 | Prometheus | Envoy metrics scraping 
| Istio control plane | 15012 | Envoy | Envoy access to istiod
| Istio control plane | 15014 | Prometheus | Prometheus scraping
| Istio control plane | 15017 | Kubernetes API Server  | Webhook entrypoint 
| Istio ingress gateway | 8443 | External | Application ingress
| Istio ingress gateway| 15090 | Prometheus | Prometheus scraping
| Istio egress gateway | 8443 | Mesh services | Application egress
| Istio egress gateway| 15090 | Prometheus | Prometheus scraping
| Keycloak| 8080 | NGINX Ingress | Access from external client 
| Keycloak| 15090 | Prometheus | Prometheus scraping
| MySql| 15090 | Prometheus | Prometheus scraping
| MySql| 3306 | Keycloak | Keycloak datastore
| Node exporter| 9100 | Prometheus | Prometheus scraping
| Rancher | 80 | NGINX Ingress | Access from external client
| Rancher | 9443 |  Kubernetes API Server  | Webhook entrypoint 
| Prometheus | 8775 | NGINX Ingress | Access from external client 
| Prometheus | 9090 | Grafana | Acccess for Grafana UI 



