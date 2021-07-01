---
title: "Installation Profiles"
description: "Named Verrazzano configurations"
weight: 2
draft: true
---

This page describes built-in configuration profiles that can be used to simplify a Verrazzano install.  An installation
profile is a well-known configuration of Verrazzano settings that can be referenced by name, which can then be 
customized as needed.

## Profiles

The following table lists the available installation profiles for Verrazzano:

| Profile  | Description | Characteristics
| ------------- |:------------- |:------------- 
| prod | Full install, production configuration | Persistent storage <br/></br>Production Elasticsearch cluster topology
| dev | A lightweight installation, for evaluation purposes | No persistence<br/><br/>Single-node ES cluster topology
| managed-cluster | A specialized installation for managed clusters in a Multicluster topology | Minimal install<br/><br/>No local monitoring components<br/><br/>All monitoring data pushed to Admin cluster<br/><br/>No local ATN/ATZ, performed by Admin cluster

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

### dev Profile

Basic `dev` profile:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  profile: dev
```

### prod Profile

Basic `prod` profile:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: my-verrazzano
spec:
  profile: prod
```

### managed-cluster Profile

Basic `managed-cluster` profile:

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
            claimName: mysql  # Use the "mysql" PVC template for the MySQL volume configuration
  volumeClaimSpecTemplates:
  - metadata:
      name: mysql      
    spec:
      resources:
        requests:
          storage: 8Gi
```