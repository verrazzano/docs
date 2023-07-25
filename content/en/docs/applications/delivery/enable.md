---
title: "Enable and Configure Argo CD"
weight: 5
draft: false
aliases:
  - /docs/applications/argo-cd/enable
---

### Enable Argo CD

1. Install Verrazzano and set up a multicluster environment by following these [instructions]({{< relref "/docs/setup/mc-install/multicluster#install-verrazzano" >}}).
<br>
  a. Because Argo CD is _not_ enabled by default, you must first [enable argoCD]({{< relref "/docs/setup/modify-installation#pre-installation" >}}) on the _admin_ cluster. <br>
  b. When you [register managed clusters]({{< relref "/docs/setup/mc-install/multicluster#register-the-managed-cluster" >}}), they are automatically registered in Argo CD.
2. Access the Argo CD console using the instructions at [Access Verrazzano]({{< relref "/docs/setup/access#the-argo-cd-console" >}}).
3. After you set up your application in the Argo CD console, those registered clusters will be available for you to select, deploy, and manage applications.

### Configure repositories

In the Argo CD console, configure repositories that will contain the Kubernetes resources for deploying an application.

The following is a sample procedure to configure a private Git repository through HTTPS.
1. Log in to the Argo CD console.
2. In the left navigation, click **Settings**.
3. Click **Repositories**.
3. Click **Connect Repo**.
4. Select **VIA HTTPS** as the connection method.
5. For **Project**, specify **default**.
<br>**NOTE**: Unless they are grouped together, all the projects are defined in the `default` level.
6. For **Repository URL**, provide the required URL.
7. If it is a private repository and a user name and password is required to connect to the repository, enter the required credentials.
<br>**NOTE**: The other fields are optional and based on how the Git repository is configured.
9. Click **Connect** and verify that the connection status displayed is `Successful`.
