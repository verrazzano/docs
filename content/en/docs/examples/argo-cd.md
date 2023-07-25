---
title: "Continuous deployment example with Argo CD"
linkTitle: Argo CD
weight: 4
aliases:
  - /docs/samples/argo-cd
---

### Before you begin

Enabled and configure Argo CD using the instructions [here]({{< relref "/docs/applications/delivery/enable.md" >}}).

### Deploy a sample application

To deploy applications in a custom namespace, create Argo CD applications that specify the Git repository path, which Argo CD requires to synchronize and deploy the applications in the specified namespace.

**NOTE**: You can either pre-create a namespace and label it or auto-create a namespace when deploying an application. In this example, we will auto-create a namespace.

This example provides information about how to deploy the `Hello-helidon` application. The `Hello-helidon` application and component YAML files are available at [Hello World Helidon]({{< ghlink raw=false path="examples/helidon-config" >}}).

1. Log in to the Argo CD console.
2. Click **New App**.
3. Specify a name for the application.
4. For **Project Name**, select **default**.
5. Select the **Sync Policy** option `Automatic`.
<br>By default, every three minutes, Argo CD checks the specified Git repository and synchronizes the updates in Kubernetes to the Git repository
6. In the **Sync Options** section, select **Auto-Create Namespace**.
<br>By auto-creating the namespace, the application will be deployed outside of the service mesh.
7. Under the **Source** section, enter the following:
    - **Repository URL**: https://github.com/verrazzano/verrazzano/
    - **Revision**: `{{<release_branch>}}`
    - **Path**: Path in the repository where the Kubernetes resource definitions are listed. For example: `examples/helidon-config`
7. Under the **Destination** section, do the following:
    - **Cluster URL**: Select the cluster to which you want to deploy the applications.
    - **Namespace**: Specify the namespace in which you want to deploy the applications. The instructions in this sample use `hello-helidon` as the namespace.
9. Click **Create**.
<br> This creates the Argo CD application and a pictorial representation of the deployed applications is displayed.

### Verify the deployed application

The Hello World Helidon microservices application implements a REST API endpoint, `/config`, which returns a message `{"message":"Hello World!"}` when invoked.

**NOTE**:  The following instructions assume that you are using a Kubernetes environment such as OKE. Other environments or deployments may require alternative mechanisms for retrieving addresses, ports, and such.

Follow these steps to test the endpoints.

1. Get the generated host name for the application.

   ```
   $ HOST=$(kubectl get gateways.networking.istio.io hello-helidon-helidon-config-appconf-gw \
        -n hello-helidon \
        -o jsonpath='{.spec.servers[0].hosts[0]}')
   $ echo $HOST

   # Sample output
   helidon-config-appconf.hello-helidon.11.22.33.44.nip.io
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
You can access them according to the directions [here]({{< relref "/docs/setup/access/#get-the-consoles-urls" >}}).  

### Undeploy applications

1. Log in to the Argo CD console.
2. Select the application that you want to undeploy and then click **Delete**.
3. Enter the name of the application and then click **OK**.
<br>This deletes all the resources created by the specific application except for the namespaces.
