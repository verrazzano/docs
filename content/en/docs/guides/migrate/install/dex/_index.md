---
title: "Dex"
weight: 1
draft: false
---
This document shows you how to install dex on OCNE.

## Overview

The following is a guide of how to install dex, an identity provider that uses OpenID Connect for authenticating access to applications.

## Install dex using Helm

1. Add the dex Helm repository to the cluster:
{{< clipboard >}}
<div class="highlight">

```
$ helm repo add dex https://charts.dexidp.io
$ helm repo update
```
</div>
{{< /clipboard >}}

1. Generate a Helm configuration override file:

   For this guide, a static user and password will be configured instead of an actual identity provider.  Generate a random password and UUID.

   {{< clipboard >}}
   <div class="highlight">
   
   ```
   $ PASSWORD=$(openssl rand -base64 10)
   $ PASSWD_HASH=$(htpasswd -nbBC 10 "" ${PASSWORD} | tr -d ':\n' | sed 's/$2y/$2a/')
   $ UUID_GEN=$(uuidgen)
   ```
   </div>
   {{< /clipboard >}}

   Generate the Helm override file.

   {{< clipboard >}}
   <div class="highlight">

   ```
   $ PASSWORD=$(openssl rand -base64 10)
   $ PASSWD_HASH=$(htpasswd -nbBC 10 "" ${PASSWORD} | tr -d ':\n' | sed 's/$2y/$2a/')
   ```
   </div>
   {{< /clipboard >}}

1. foo

1. bar

