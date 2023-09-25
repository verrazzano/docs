---
title: "Deploy Applications With Argo CD"
description: "Use Argo CD to synchronize and deploy applications"
weight: 6
draft: false
aliases:
  - /docs/applications/argo-cd/deploy
---

To deploy applications in a custom namespace, create Argo CD applications that specify the Git repository path, which Argo CD requires to synchronize and deploy the applications in the specified namespace.

**NOTE**: You can either pre-create a namespace and label it or auto-create a namespace when deploying an application.

This example provides information about how to deploy the `Hello-helidon` application. The `Hello-helidon` application and component YAML files are available at [Hello World Helidon]({{< ghlink raw=false path="examples/helidon-config" >}}).

1. Log in to the Argo CD console.
2. Click **New App**.
3. Specify a name for the application.
4. For **Project Name**, select **default**.
5. Select the required **Sync Policy** option:
   - `Automatic` - By default, every three minutes, Argo CD checks the specified Git repository and synchronizes the updates in Kubernetes to the Git repository.
   - `Manual` - For manually synchronizing the updates to the Git repository, use the **Manual** option.
6. If you want to auto-create a namespace, in the **Sync Options** section, select **Auto-Create Namespace**.
<br>By auto-creating the namespace, the application will be deployed outside of the service mesh. The best practice is to pre-create the namespace and label it.
7. Under the **Source** section, enter the following:
    - **Repository URL**: https://github.com/verrazzano/verrazzano/
    - **Revision**: `{{<release_branch>}}`
    - **Path**: Path in the repository where the Kubernetes resource definitions are listed. For example: `examples/helidon-config`
7. Under the **Destination** section, do the following:
    - **Cluster URL**: Select the cluster to which you want to deploy the applications.
    - **Namespace**: Specify the namespace in which you want to deploy the applications. The instructions in this sample use `hello-helidon` as the namespace.
9. Click **Create**.
10. If you selected `Manual` as the **Sync Policy** option, then click **Sync**. In the **Synchronize Resources** section, select all the resources, and then click **Synchronize**.
<br> This creates the Argo CD application and a pictorial representation of the deployed applications is displayed.

To verify or undeploy the Argo CD application, see [Verify the deployed application]({{< relref "/docs/examples/argo-cd#verify-the-deployed-application" >}}) and [Undeploy applications]({{< relref "/docs/examples/argo-cd#undeploy-applications" >}}).
