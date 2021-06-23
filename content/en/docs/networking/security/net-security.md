---
title: "Network Security"
linkTitle: "Network Security"
description: "Verrazzano Network Security"
weight: 4
draft: true
---

Network security is critical for any software running in Kubernetes.  Verrazzano
configures network security at multiple levels for both system components and applications.

## Network Policies

Network policies are configured for all
 components to restrict IP ingress. Istio mTLS and authorization 
 polices are configured for additional layers of security to control HTTP and TCP
 access. TLS and mTLS is used across system components and applications to provide
 additional levels of network security.
 
 Network / Transport Layer Security
 By default, all pods in a Kubernetes cluster have network access all other pods over the network.  Kubernetes has a native NetworkPolicy resource that provides network level 3 and 4 security for pods, restricting both ingress and egress for a set of pods in a namespace.  A NetworkPolicy can be applied to individual pods with matching labels, or to all pods in the namespace.  For example, a namespace can be configured to only receive IP traffic from  other pods in the same namespace.  More fine grained restrictions can also be applied, for example, restricting ingress into the Elasticsearch Ingest pod from only the NGINX Ingress controller.
 
 CNI Plugin Required
 A NetworkPolicy resource needs a NetworkPolicy controller to implement the policy, otherwise the resource has no effect.  A Kubernetes CNI plugin that provides a NetworkPolicy controller, such as Calico, must be installed by the user before installing Verrazzano.  Experimentation with Calico on OKE showed that a NetworkPolicy can be used to protect the pods, both inside the Istio mesh and outside(coherence has not been tested).   Installing the CNI plugin is a user prerequisite for network security and must be done by the user before installing Verrazzano.  Calico has its own network policy custom resource, but using it would make Calico a prerequisite, Platform vendors, especially cloud providers, may have their own CNI plugin which implements a NetworkPolicy controller.
 
 Policies for System Components
 Verrazzano installs several products, referred to as components, such as Keycloak, Rancher, etc.   Verrazzano also installs internal components, such as the Verrazano application operator and the Verrazano API proxy.  Collectively, these components are called the Verrazzano installation, and do not include applications that are deployed by the user.  All of these components must be secured using a set of NetworkPolicy resources.
 
 Verrazzano will provide layer 3/4 network security by using Kubernetes NetworkPolicy to restrict network traffic for Verrazzano system components, according to the following rules:
 
 For each namespace in the installation, block all ingress to pods in the namespace and egress from the namespace, by creating a default NetworkPolicy that selects all pods in the namespace (i.e., a NetworkPolicy with an empty podSelector).
 For each pod (or collection of related pods) in a namespace, create a Network with a podSelector selecting those pods, and providing to/from rules to:
 Allow traffic from ingress controllers as needed
 Allow traffic from pods outside the namespace as needed
 Allow egress from pods in the namespace to pods (or other endpoints) outside the namespace as needed
 Allow traffic to/from designated pods within the namespace as required (for example VMI pod access should be restricted to other pods in the verrazzano-system namespace).
