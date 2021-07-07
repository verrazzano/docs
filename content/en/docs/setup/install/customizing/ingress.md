---
title: Customizing the NGINX Ingress
description: Instructions for customizing the Verrazzano NGINX installation
linkTitle: Customizing NGINX
Weight: 9
draft: true
---

You can customize the NGINX ingress configuration using Helm overrides.  For example, to override the configuration of the
`nginx-controller`,  apply the following customization to the Verrazzano CRD.

```shell
spec:
 components:
  ingress:
   nginxInstallArgs:
   # nginx Helm overrides can be specified here
   - name: <name of the nginx Helm override e.g. controller.nodeSelector.ingress-ready>
     value: <value of the nginx Helm override e.g. "true">
     setString: true
```
