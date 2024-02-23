---
title: "OAuth2 Proxy"
weight: 1
draft: false
---
This document shows you how to install OAuth2 Proxy on OCNE.

## Overview

The following is a guide of how to install OAuth2 Proxy, a reverse proxy that provides authentication with identity providers.

## Install OAuth2 Proxy using Helm

1. Add the OAuth2 Proxy repository to the cluster:
{{< clipboard >}}
<div class="highlight">

```
$ helm repo add oauth2-proxy https://oauth2-proxy.github.io/manifests
$ helm repo update
```
</div>
{{< /clipboard >}}