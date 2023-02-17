---
title: "Argo CD"
weight: 1
description: "Use Argo CD to deploy and undeploy applications"
---

Argo CD is a Kubernetes deployment tool that uses Git repositories as the source of truth. It monitors running applications and compares the deployed state against the desired one in Git. Argo CD lets you visualize the differences and provides methods to automatically or manually update the live state with the desired target state. For more information, see the [Argo CD documentation](https://argo-cd.readthedocs.io/en/stable/).

## Before you begin

- Install Verrazzano by following the [installation]({{< relref "/docs/setup/install/installation.md" >}}) instructions.
- Enable Argo CD using the instructions at [Enable Argo CD]({{< relref "/docs/setup/install/register-argocd/register-argocd#enable-argo-cd" >}}).
- Access the Argo CD console using the instructions at [Access Verrazzano]({{< relref "/docs/access#the-argo-cd-console" >}}).



## Configure repositories

In the Argo CD console, configure repositories that will contain the Kubernetes resources for deploying an application.

The following is a sample procedure to configure a private Git repository through HTTPS.
1. Log in to the Argo CD console.
2. In the left navigation, click **Settings**.
3. Click **Repositories**.
3. Click **Connect Repo**.
4. Select **VIA HTTPS** as the connection method.
5. For **Project**, specify **default**.
<br>**Note**: Unless they are grouped together, all the projects are defined in the `default` level.
6. For **Repository URL**, provide the required URL.
7. If it is a private repository and a user name and password is required to connect to the repository, enter the required credentials.
<br>**Note**: The other fields are optional and based on how the Git repository is configured.
9. Click **Connect** and verify that the connection status displayed is `Successful`.

## Deploy applications

To deploy applications in a custom namespace, create Argo CD applications that specify the Git repository path, which Argo CD requires to synchronize and deploy the applications in the specified namespace.

This example provides information about how to deploy the `Hello-helidon` application. The `Hello-helidon` application and component YAML files are available at [Hello World Helidon](https://github.com/verrazzano/verrazzano/tree/master/examples/helidon-config).

1. Log in to the Argo CD console.
2. Click **New App**.
3. Specify a name for the application.
4. For **Project Name**, select **default**.
5. Select the required **Sync Policy** option:
   - `Automatic` - By default, every three minutes, Argo CD checks the specified Git repository and synchronizes the updates in Kubernetes to the Git repository.
   - `Manual` - For manually synchronizing the updates to the Git repository, use the **Sync** option.
6. In the **Sync Options** section, select **Auto-Create Namespace**.
7. Under the **Source** section, enter the following:
    - **Repository URL**: https://github.com/verrazzano/verrazzano/
    - **Revision**: `master`
    - **Path**: Path in the repository where the Kubernetes resource definitions are listed. For example: `examples/helidon-config`
7. Under the **Destination** section, do the following:
    - **Cluster URL**: Select the cluster to which you want to deploy the applications.
    - **Namespace**: Specify the namespace in which you want to deploy the applications.
9. Click **Create**.
10. If you selected `Manual` as the **Sync Policy** option, then click **Sync**.
<br> This creates the Argo CD application and a pictorial representation of the deployed applications is displayed.

## Verify the deployed application

The Hello World Helidon microservices application implements a REST API endpoint, `/config`, which returns a message `{"message":"Hello World!"}` when invoked.

**NOTE**:  The following instructions assume that you are using a Kubernetes environment such as OKE. Other environments or deployments may require alternative mechanisms for retrieving addresses, ports, and such.

Follow these steps to test the endpoints.

1. Get the generated host name for the application.

   ```
   $ HOST=$(kubectl get gateways.networking.istio.io hello-helidon-hello-helidon-gw \
        -n hello-helidon \
        -o jsonpath='{.spec.servers[0].hosts[0]}')
   $ echo $HOST

   # Sample output
   hello-helidon-appconf.hello-helidon.11.22.33.44.nip.io
   ```

1. Get the `EXTERNAL_IP` address of the `istio-ingressgateway` service.
   ```
   $ ADDRESS=$(kubectl get service \
        -n istio-system istio-ingressgateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   $ echo $ADDRESS

   # Sample output
   11.22.33.44
   ```   

1. Access the application.

   * **Using the command line**
     ```
     $ curl -sk \
        -X GET \
        https://${HOST}/config \
        --resolve ${HOST}:443:${ADDRESS}

     # Expected response output
     {"message":"Hello World!"}
     ```
     If you are using `nip.io`, then you do not need to include `--resolve`.
   * **Local testing with a browser**

     Temporarily, modify the `/etc/hosts` file (on Mac or Linux)
     or `c:\Windows\System32\Drivers\etc\hosts` file (on Windows 10),
     to add an entry mapping the host name to the ingress gateway's `EXTERNAL-IP` address.
     For example:
     ```
     11.22.33.44 hello-helidon.example.com
     ```
     Then you can access the application in a browser at `https://<host>/config`.

     - If you are using `nip.io`, then you can access the application in a browser using the `HOST` variable (for example, `https://${HOST}/config`).  
     - If you are going through a proxy, then you may need to add `*.nip.io` to the `NO_PROXY` list.

   * **Using your own DNS name**

     Point your own DNS name to the ingress gateway's `EXTERNAL-IP` address.
     * In this case, you would need to edit the `hello-helidon-app.yaml` file
       to use the appropriate value under the `hosts` section (such as `yourhost.your.domain`),
       before deploying the `hello-helidon` application.
     * Then, you can use a browser to access the application at `https://<yourhost.your.domain>/config`.     

1. A variety of endpoints associated with the deployed application are available to further explore the logs, metrics, and such.
You can access them according to the directions [here]({{< relref "/docs/access/#get-the-consoles-urls" >}}).  

## Undeploy applications

1. Log in to the Argo CD console.
2. Select the application that you want to undeploy and then click **Delete**.
3. Enter the name of the application and then click **OK**.
<br>This deletes all the resources created by the specific application except for the namespaces.
