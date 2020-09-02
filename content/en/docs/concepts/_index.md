---
title: "Concepts"
weight: 3
bookCollapseSection: false
---

<!---
>
> Notes to Author - need to include the following information within the Concepts section:
>
> * Detailed introduction of the Verrazzano Enterprise Container Platform
> * Architecture of the system (including a drawing)
> * Components of the platform
> * What gets installed where
> * Application Model and Application Binding
> * Working with CI/CD systems
> * infrastructure Management
--->

Verrazzano Enterprise Container Platform is a curated collection of open source and Oracle-authored components that form a complete platform for modernizing existing applications, and for deploying and managing your container applications across multiple Kubernetes clusters.

Most enterprises have applications that are related to each other, may even be dependant on one another, and are best managed together. For example, if an application system has a front-end web application, a back-end Java EE application, and a series of microservices that provide additional functionality, that application is best managed and monitored as a unit, even if some of the components need to run in different environments or on different clouds.

With Verrazzano Enterprise Container Platform, you can create a model of this application system, and then manage the life cycle of all of the components from a single tool. Verrazzano automatically creates a pre-wired monitoring stack (Prometheus, Grafana, and the EFK stack) for the complete application so that you can view runtime status, troubleshoot, and set up alerts for all of the application components.

Verrazzano Enterprise Container Platform includes the following capabilites:

* Hybrid and multi-cluster workload management
* Special handling for WebLogic, Coherence, and Helidon applications
* Multi-cluster infrastructure management
* Integrated and pre-wired application monitoring
* Integrated security
* DevOps and GitOps enablement

## Hybrid and multi-cluster workload management
<!---
Describe model, binding, placement, etc.
Both model and binding are meant to simple but flexible
--->

## Special handling for WebLogic, Coherence, and Helidon applications
Verrazzano builds on the WebLogic Kubernetes Toolkit, which includes facilities to model your WebLogic application, create a container image of the WebLogic domain, and then manage the domain in containers running in Kubernetes.

With Verrazzano, you can include WebLogic domains in your Verrazzano Application Model. Within the model, you can specify XXX

## Multi-cluster infrastructure management

## Integrated and pre-wired application monitoring

## Integrated security

## DevOps and GitOps enablement

# Verrazzano Architecture

# Verrazzano Components
<!---
* Oracle-authored components, including custom resource definitions and microperators
* Istio
* Rancher
* Prometheus
* Grafana
* ElasticSearch
* Fluentd
* Kibana
* Keycloak
* Cert Manager
--->
