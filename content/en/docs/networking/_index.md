---
title: "Networking"
description: ""
weight: 7
draft: true
---

## Overview
 
A Verrazzano instance is comprised of both Verrazzano components and several 
third party products. Collectively, these components are called the Verrazzano 
system components.  In addition, a Verrazzano instance can include applications 
deployed by the user, after Verrazzano is installed.  Applications can also be
referred to as components, not to be confused with OAM components.  

All of the system components and applications use the network to some degree.  Verrazzano 
configures networking to provide network security and traffic management.  Network 
settings are configured both at installation and during runtime as applications as are 
deployed into the Kubernetes cluster.

A summary of the network related configuration follows.

### Network configuration during installation
Verrazzano does the following as it relates to networking:
1. installs and configures NGINX Ingress Controller
1. creates Ingress resources for system components
1. installs and configures Istio
1. enables strict mTLS for the mesh by creating an Istio PeerAuthentication resource
1. creates an Istio egress gateway service
1. creates an Istio ingress gateway service
1. configures several Verrazzano system components to be in the mesh.  
1. optionally installs ExternalDNS and creates DNS records
1. creates certificates required by TLS used by system components
1. creates certificates required by Kubernetes API server to call webhook
1. creates NetworkPolicies for all of the system components.

### Network configuration during application lifecycle
Verrazzano does the following as it relates to applications being deployed and terminated
1. optionally creates an Istio Gateway and VirtualService resources
1. creates Istio AuthorizationPolicies as needed
1. creates Istio DestinationRules as needed
1. optionally creates a self-signed certificate for the application
1. optionally creates DNS records using external DNS.
