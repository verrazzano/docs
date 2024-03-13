---
title: "Networking"
description: ""
weight: 10
draft: false
---

{{< alert title="NOTE" color="primary" >}}
Premier Support for Oracle Verrazzano Enterprise Container Platform will end on October 31, 2024, as documented at https://www.oracle.com/us/assets/lifetime-support-middleware-069163.pdf. After that date, Oracle Verrazzano will remain in Sustaining Support indefinitely. There will be no further releases, updates, or fixes.
For more details, see My Oracle Support [Note 2794708.1](https://support.oracle.com/epmos/faces/DocumentDisplay?_afrLoop=33881630232591&id=2794708.1).
{{< /alert >}}

A Verrazzano instance is comprised of both Verrazzano components and several
third party products. Collectively, these components are called the Verrazzano
system components.  In addition, after Verrazzano is installed,
a Verrazzano instance can include applications deployed by the user.  Applications
can also be referred to as components, not to be confused with OAM Components.  

All of the system components and applications use the network to some degree.  Verrazzano
configures networking to provide network security and traffic management.  Network
settings are configured both at installation and during runtime as applications are
deployed into the Kubernetes cluster.

## High-level overview
The following diagram shows the high-level overview of Verrazzano networking
using ExternalDNS and Let's Encrypt for certificates. ExternalDNS and cert-manager
both run outside the mesh and connect to external services using TLS.  This diagram
does not show Prometheus scraping.

Verrazzano system traffic enters a platform load balancer over TLS and is routed to the
Ingress NGINX Controller, where TLS is terminated.  From there, the traffic is routed
to one of the system components in the mesh over mutual TLS authentication (mTLS), or using HTTP to a system component,
outside the mesh.  

Application traffic enters a second Oracle Cloud Infrastructure load balancer over TLS and is routed to the
Istio ingress gateway, where TLS is terminated. From there, the traffic is routed
to one of several applications using mTLS.

**NOTE**: Applications can be deployed outside the mesh, but the Istio ingress gateway
will send traffic to them using plain text.  You need to do some additional configuration to
enable TLS passthrough, as described at [Istio Gateway Passthrough](https://istio.io/latest/docs/tasks/traffic-management/ingress/ingress-sni-passthrough/).

### High-level network diagram

![](/docs/images/networking/network-high-level.png)

## Platform network connectivity
A Kubernetes cluster is installed on a platform, such as Oracle OKE,
an on-premises installation, a hybrid cloud topology, or such.  Verrazzano interfaces only
with Kubernetes; it has no knowledge of platform topology or network security. _You_ must
ensure that there is network connectivity.  For example, the
ingresses might use a platform load balancer that provides the entry point into the
cluster for Verrazzano consoles and applications.  These load balancer IP addresses must be
accessible for your users.  In the multicluster case, clusters might be on
different platform technologies with firewalls between them. Again, you must
ensure that the clusters have network connectivity.


## Network configuration during installation
A summary of the network-related configuration follows.

Verrazzano does the following as it relates to networking:
1. Installs and configures Ingress NGINX Controller.
1. Creates Ingress resources for system components.
1. Installs and configures Istio.
1. Enables strict mTLS for the mesh by creating an Istio PeerAuthentication resource.
1. Creates an Istio egress gateway service.
1. Creates an Istio ingress gateway service.
1. Configures several Verrazzano system components to be in the mesh.  
1. Optionally, installs ExternalDNS and creates DNS records.
1. Creates certificates required by TLS, used by system components.
1. Creates certificates required by Kubernetes API server to call a webhook.
1. Creates NetworkPolicies for all of the system components.

## Network configuration during application life cycle
Verrazzano does the following as it relates to applications being deployed and terminated:
1. Optionally, creates an Istio Gateway and VirtualService resources.
1. Creates Istio AuthorizationPolicies, as needed.
1. Creates Istio DestinationRules, as needed.
1. Optionally, creates a self-signed certificate for the application.
1. Optionally, creates DNS records using ExternalDNS.
