---
title: "Istio Integration"
linkTitle: "Istio"
description: "Verrazzano Istio Integration" 
weight: 2
draft: true
---

Istio is a feature rich service mesh used by Verrazzano for some traffic management and security.
This document discusses how Verrazzano uses Istio.

## Istio Mesh
A service mesh is an infrastructure layer that provides certain capabilities like security, observabilty, load balancing,
etc. for services used by an application.  Istio defines a service mesh here [Istio Service Mesh](https://istio.io/latest/about/service-mesh/).
What does it mean for a service to be in the mesh?  Basically, it means that there is an Envoy proxy in front of every 
service intercepting inbound and outbound network traffic for that service.  In Kubernetes, that proxy happens to be a sidecar 
running in the all the pods used by the service.




## Traffic Management
## mTLS
## Access Control
## Prometheus

