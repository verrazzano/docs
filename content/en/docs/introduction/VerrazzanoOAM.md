---
title: "Verrazzano and the Open Application Model"
linkTitle: Open Application Model
weight: 3
draft: false
aliases:
  - /docs/concepts/verrazzanooam
---

Open Application Model (OAM) is a runtime-agnostic specification for defining cloud native applications; it allows developers to focus on the application instead of the complexities of a particular runtime infrastructure.  OAM provides the [specification](https://github.com/oam-dev/spec) for several file formats and rules for a runtime to interpret.  Verrazzano uses OAM to enable the definition of a composite application abstraction and makes OAM constructs available within a `VerrazzanoApplication` YAML file.  Verrazzano provides the flexibility to combine what you want into a multicloud enablement. It uses the `VerrazzanoApplication` as a means to encapsulate a set of components, scopes, and traits, and deploy them on a selected cluster.

OAM's workload concept makes it easy to use many different workload types.  Verrazzano includes specific workload types with special handling to deploy and manage those types, such as WebLogic, Coherence, and Helidon.  OAM's flexibility lets you create a grouping that is managed as a unit, although each component can be scaled or updated independently.

## How does OAM work?
OAM has five core concepts:

- Workloads - Declarations of the kinds of resources supported by the platform and the OpenAPI schema for that resource.  Most Kubernetes CRDs can be exposed as workloads.  Standard Kubernetes resource types can also be used
  (for example, Deployment, Service, Pod, ConfigMap).
- Components - Wrap a workload resource's specification data within OAM specific metadata.  
- Application Configurations - Describe a collection of components that comprise an application.  This is also where customization (such as, environmental) of each component is done.  Customization is achieved using scopes and traits.
- Scopes - Apply customization to several components.  
- Traits - Apply customization to a single component.

![](/docs/introduction/oam-app.svg)
