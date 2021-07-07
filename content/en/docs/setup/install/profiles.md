---
title: "Install Profiles"
description: "Using named Verrazzano configurations to simplify an installation"
weight: 2
draft: false
---

This document describes built-in configuration profiles that you can use to simplify a Verrazzano installation.  An installation
profile is a well-known configuration of Verrazzano settings that can be referenced by name, which can then be 
customized as needed.

## Profiles

The following table lists the available installation profiles for Verrazzano:

| Profile  | Description | Characteristics
| ------------- |:------------- |:------------- 
| prod | Full install, production configuration | Default Profile<br/>- Persistent storage <br/>- Production Elasticsearch cluster topology
| dev | Development/Evaluation configuration | Lightweight installation<br/>- For evaluation purposes<br/>- No persistence<br/>- Single-node Elasticsearch cluster topology
| managed-cluster | A specialized installation for managed clusters in a Multicluster topology | Minimal install for a managed cluster<br/>- No local monitoring components<br/>- All monitoring data pushed to Admin cluster<br/>- No local ATN/ATZ, performed by Admin cluster<br/>- The cluster must be registered with an admin cluster In order leverage [multicluster](../../../concepts/verrazzanomulticluster) features

### Using an Install Profile

In order to use a profile to install Verrazzano, simply set the profile name in the `profile` field of your
Verrazzano custom resource.

For example, to use the `dev` profile:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  profile: dev
```

To use another profile, simply replace `dev` in the example above with `prod` or `managed-cluster` to use
one of those profiles.

### Customizing an Install Profile

You can also override the profile settings for any component regardless of the profile.  The following example 
illustrates a configuration that uses a customized `dev` profile:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-dev-example
spec:
  profile: dev
  components:
    prometheus:
      enabled: false
    grafana:
      enabled: false
    keycloak:
      mysql:
        volumeSource:
          persistentVolumeClaim:
            claimName: mysql
  volumeClaimSpecTemplates:
  - metadata:
      name: mysql      
    spec:
      resources:
        requests:
          storage: 8Gi
```

The example configuration above does the following:

* Disables the Prometheus and Grafana components smaller monitoring footprint.
* Configures a small 8Gi persistent volume for the MySQL instance used by Keycloak to provide more
  stability for the Keycloak service.
  
See [Customizing an Install](/docs/setup/install/customizing) for details on how to customize each 
Verrazzano component.

### Profile Configurations

The following table describes the Verrazzano components that are installed with each profile.  Note that you can
customize any Verrazzano install, regardless of the profile used.

| Component | dev | prod | managed-cluster 
| ------------- |:-------------: |:-------------: |:-------------: 
| Istio | ✔️ | ✔️ | ✔️
| NGINX | ✔️ | ✔️ | ✔️
| Cert-Manager | ✔️ | ✔️ | ✔️
| External-DNS |️ |️ | 
| Prometheus | ✔️ | ✔️ | ✔️ 
| Elasticsearch | ✔️ | ✔️ |
| Console | ✔️ | ✔️ |
| Kibana | ✔️ | ✔️ |  
| Grafana | ✔️ | ✔️ |  
| Rancher | ✔️ | ✔️ |    
| Keycloak | ✔️ | ✔️ |  

The following table describes the persistent storage configurations for components in each profile:

| Component | dev | prod | managed-cluster
| ------------- |:-------------:|:-------------:|:-------------: 
| Elasticsearch<br/>(Master and Data nodes) | | 50Gi | 50Gi
| Prometheus | | 50Gi | 50Gi
| Grafana | | 50Gi | 50Gi
| Keycloak | | 50Gi | 50Gi

### Profile-independent Defaults

The following table shows the settings for components that are profile-independent (consistent across
all profiles unless overridden):

| Component | Default 
| -------------|-------------
| DNS |  Wildcard DNS provider [nip.io](https://nip.io) 
| Certificates | Uses the [Cert-Manager](https://cert-manager.io/) self-signed [ClusterIssuer](https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.ClusterIssuer) for certificates 
| Ingress-type | Defaults to`LoadBalancer` service type for the ingress

See [Customizing an Install](/docs/setup/install/customizing) for details on how to customize each
Verrazzano component.