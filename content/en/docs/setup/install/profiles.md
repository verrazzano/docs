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
| managed-cluster | A specialized installation for managed clusters in a Multicluster topology<br/>- In order to take full advantage of [multicluster](../../../concepts/verrazzanomulticluster) features, the managed cluster should be registered with an admin cluster. | Minimal install<br/>- No local monitoring components<br/>- All monitoring data pushed to Admin cluster<br/>- No local ATN/ATZ, performed by Admin cluster

### Component Profile Matrix

The following table describes the Verrazzano components that are installed with each profile.  Note that you can
customize any Verrazzano install, regardless of the profile used.

| Component | dev | prod | managed-cluster 
| ------------- |:-------------: |:-------------: |:-------------: 
| Istio | ✅ | ✅ | ✅
| NGINX | ✅ | ✅ | ✅
| Cert-Manager | ✅ | ✅ | ✅
| External-DNS | ✅ | ✅ | ✅
| Console | ✅ | ✅ | ❌
| Prometheus | ✅ | ✅ | ✅ 
| Elasticsearch | ✅ | ✅ | ❌  
| Kibana | ✅ | ✅ | ❌ 
| Grafana | ✅ | ✅ | ❌ 
| Rancher | ✅ | ✅ | ❌   
| Keycloak | ✅ | ✅ | ❌ 

## Profile Examples

### Basic dev Profile

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  profile: dev
```

### Basic prod Profile

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  profile: prod
```

### Basic managed-cluster Profile

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  profile: managed-cluster
```

### Customized dev Profile

The following example illustrates a configuration that uses a customized `dev` profile.  It disables
the Prometheus and Grafana components and uses an 8Gi persistent volume for the MySQL instance
used by Keycloak.  This configuration might be useful in the cases where the more lightweight `dev` profile
is desirable as the starting point but uses a smaller monitoring footprint and persistence to provide more 
stability for the Keycloak service.

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