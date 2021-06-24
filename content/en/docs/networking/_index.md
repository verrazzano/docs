---
title: "Networking"
description: ""
weight: 7
draft: false
---

## Overview

A Verrazzano installation is comprised of several third party products, such as Keycloak, 
Rancher, etc.  An installation also inclused internal components, such as the 
Verrazano application operator and the Verrazano platform operator.  Collectively, 
these components are called the Verrazzano system components, and do not include 
applications deployed by the user.
 
Verrazzano configures networking components including Istio and NGINX to provide network security, 
and traffic management.  Network settings are configured both at installation and during 
runtime as applications as are deployed into the Kubernetes cluster.

### Network configuration during installation
The following material is covered in detail in this document.
This is just a summary of the network related configuration.

Verrazzano does the following as it relates to networking:

1. installs and configures NGINX Ingress controller
1. creates Ingress resources for system components
1. installs and configures Istio
1. enables strict mTLS for the mesh by creating an Istio PeerAuthentication resource
1. creates an Istio egress gateway service
1. creates an Istio ingress gateway service
1. configures several Verrazzanao system components to be in the mesh.  
1. optionally installs externalDNS and creates DNS records
1. creates certificates required by TLS used by system components
1. creates certificates required by Kubernetes API server to call webhook
1. creates NetworkPolices for all of the system components.

### Network configuration during application lifecycle
Verrazzano does the following as it relates to applications being deployed and terminated
1. optionally creates an Istio Gateway and VirtualService resources
1. creates Istio AuthorizationPolicies as needed
1. creates Istio DestinationRules as needed
1. optionally creates a self-signed certificate for the application
1. optionally creates DNS records using external DNS.
