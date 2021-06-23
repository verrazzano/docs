---
title: "Networking"
description: ""
weight: 8
draft: false
---

A Verrazzano installation is comprised of components, products, and applications 
that all use the network at different layers.  Verrazzano configures and uses several
networking technologies including Istio and NGINX to provide network security, 
traffic management, monitoring, and logging.  Network settings are configured both
at installation and during runtime as applications are deployed into the 
Kubernetes cluster.

To understand how Verrazzano uses the network, basic understanding of both Kubernetes
networking and Istio are required.  While this document provides introduction to both
technologies, you should consult the respective product documentation for additional 
technical details.  The intention is to explain enough so that you can understand how Verrazzano uses 
the underlying network.  Areas such are ingress and TLS are related to the 
certificates documentation in the security section, please consult that as needed.

## Overview
There are two broad categories of software used in a Verrazzano installation:
system components and user applications.  System components are the products installed
by Verrazzano, like Elasticsearch and Prometheus, along with Verrazzano operators, etc.
Applications are OAM applications deployed into the cluster by the user.  From a networking
perspective, the biggest difference between the two categories is that system components
  have a fixed topology and lifecycle for the most part, whereas applications have a dynamic topology
  and lifecycle.  Applications are deployed, scaled, terminated on demand and may consist of any
  number of services that require network connectivity.  The other main difference is that
  applications cannot and do not communicate with the Kubernetes API server. In contrast, system
  components such as controllers must call the API server and are called back by the API server for
  webhook validations.

