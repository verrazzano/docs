---
title: "Configuring Access to an Insecure Private Registry"
description: ""
weight: 15
draft: false
---

A private Docker registry is called an [insecure registry](https://docs.docker.com/registry/insecure/) when it is configured for access using a self-signed certificate or over an unencrypted HTTP connection. 
For example, for the [Oracle Cloud Native Environment platform]({{< relref "/docs/setup/install/prepare/platforms/OLCNE/_index.md" >}}), insecure registries must be configured in `/etc/containers/registries.conf` as follows on the worker nodes:
{{< clipboard >}}
<div class="highlight">

```
 [registries]
    [registries.insecure]
      registries = ["insecure-registry-1:1001/registry1","insecure-registry-2:1001/registry2"]
 ```
</div>
{{< /clipboard >}}
