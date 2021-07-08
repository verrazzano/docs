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
| prod | Full install, production configuration | Default Profile<br/>- Full install<br/>- Persistent storage <br/>- Production Elasticsearch cluster topology
| dev | Development/Evaluation configuration | Lightweight installation<br/>- For evaluation purposes<br/>- No persistence<br/>- Single-node Elasticsearch cluster topology
| managed-cluster | A specialized installation for managed clusters in a Multicluster topology | Minimal install for a managed cluster<br/>- Cluster must be registered with an admin cluster to leverage [multicluster](../../../concepts/verrazzanomulticluster) features

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
uses a customized `dev` profile to configure a small 8Gi persistent volume for the MySQL instance used by Keycloak to
provide more stability for the Keycloak service:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: custom-dev-example
spec:
  profile: dev
  components:
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

#### Profiles and Prometheus Configurations

The following table describes the configurations for Prometheus and Grafana in each profile:

| Profile | Prometheus | Grafana
| ------------- |:------------- |:-------------
| prod | 1 replica, 128M memory, 50Gi storage | 1 replica, 48M memory, 50Gi storage
| dev | 1 replica, 128M memory, ephemeral storage | 1 replica, 48M memory, ephemeral storage
| managed-cluster | 1 replica, 128M memory, 50Gi storage | Not installed

#### Profiles and Elasticsearch Configurations

The following table describes the Kibana and Elasticsearch cluster topology in each profile:

| Profile | Elasticsearch | Kibana
| ------------- |:------------- |:-------------
| prod | 3 master replicas, 1.4Gi memory, 50Gi storage<br/>1 ingest replica, 2.5Gi memory<br/>2 data replicas, 4.8Gi memory, 50Gi storage | 1 replica, 192M memory, ephemeral storage
| dev | 1 master/data/ingest replica, 1Gi memory, ephemeral storage  | 1 replica, 192M memory, ephemeral storage
| managed-cluster | Not installed | Not installed

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