---
title: "Verrazzano and the Open Application Model"
weight: 8
bookCollapseSection: true
---

Open Application Model (OAM) is a runtime-agnostic specification for defining cloud native applications, it allows developers to focus on the application instead of the complexities of a particular runtime infrastructure.  OAM is the [specification](https://github.com/oam-dev/spec) of several file formats and rules for a runtime to interpret.  Verrazzano uses OAM to enable the definition of a composite application abstraction and makes OAM constructs available within a VerrazzanoApplication yaml file.  Verrazzano provides flexibility to combine what you want into a multi-cloud enablement: Verrazzano uses the VerrazzanoApplication as a means to encapsulate a set of components, scopes, and traits, and deploy them on a selected cluster. 

OAM's workload concept makes it easy to pick up many different workload types.  Verrazzano includes some specific workload types with special handling that make it easy to deploy and manage those types, including WebLogic, Coherence, and Helidon.  OAM provides the flexibility to combine what you want into a grouping that is managed as a unit, although each component can be scaled or updated independently. 

### How does OAM work?
OAM has five core concepts

- Workloads - Declarations of the kinds of resources supported by the platform and the OpenAPI schema for that resource.  Most Kubernetes CRDs can be exposed as workloads.  Standard Kubernetes resource types can also be used (e.g. Deployment, Service, Pod, ConfigMap).
- Components - Wrap a workload resource's spec data within OAM specific metadata.  
- ApplicationConfigurations - Describes a collection of components that comprise an application.  This is also where customization (e.g. environmental) of each component is done.  Customization is done using scopes and traits. 
- Scopes - These are used for customizations that apply to several components.  
- Traits - These are used for customizations that apply to a single component.

### Getting started with OAM

#### What needs to be created

#### Deploying to a remote cluster

#### See reference section on VerrazzanoApplication and other component types

