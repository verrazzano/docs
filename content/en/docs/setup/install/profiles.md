---
title: "Installation Profiles"
description: "Installation Profiles"
weight: 2
draft: true
---

This page describes built-in configuration profiles that can be used to simplify a Verrazzano install.  An installation
profile is a well-known configuration of Verrazzano settings that can be referenced by name, which can then be 
customized as needed.

## Profiles

| Profile | Description
| ------------- |:------------- 
| prod |
| dev |
| managed-cluster |


| Component | dev | prod | managed-cluster | Comments
| ------------- |:------------- |:------------- |:------------- |:------------- 
| Console | Y | Y | N |
| Prometheus | Y | Y | Y |
| Elasticsearch | Y | Y | N | 
| Kibana | Y | Y | N |
| Grafana | Y | Y | N |
| Rancher | Y | Y | N | In a managed-cluster configuration, 
| Keycloak | Y | Y | N | In a managed-cluster configuration, all authentication is performed by the Admin cluster

## Using a Profile



