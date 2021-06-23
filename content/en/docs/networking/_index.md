---
title: "Networking"
description: ""
weight: 1
draft: false
---

A Verrazzano installation is comprised of several third party products, such as Keycloak, 
Rancher, etc.  An installation also inclused internal components, such as the 
Verrazano application operator and the Verrazano platform operator.  Collectively, 
these components are called the Verrazzano system components, and do not include 
applications deployed by the user.
 
Verrazzano configures networking components including Istio and NGINX to provide network security, 
and traffic management.  Network settings are configured both at installation and during 
runtime as applications as are deployed into the  Kubernetes cluster.


## Overview
From a networking perspective, the one of the main difference between the system components
and applications is that system components have a fixed topology and lifecycle for the most part, 
whereas applications have a dynamic topology and lifecycle.  Applications are deployed, 
scaled, terminated on demand and may consist of any number of services that require 
network connectivity.  The other main difference is that applications cannot and do 
not communicate with the Kubernetes API server. In contrast, system components such 
as controllers must call the API server and are called back by the API server for
webhook validations.

