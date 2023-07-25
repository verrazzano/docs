---
title: "Multicluster ToDo List"
linktitle: "ToDo List"
weight: 3
aliases:
  - /docs/samples/multicluster/todo-list
---

ToDo List is an example application containing a WebLogic component.
For more information and the source code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).

## Before you begin

* Set up a multicluster Verrazzano environment following the [installation instructions]({{< relref "/docs/setup/mc-install/multicluster.md" >}}).
* The example assumes that there is a managed cluster named `managed1` associated with the multicluster environment.
If your environment does not have a cluster of that name, then you should edit the deployment files and change the cluster name
listed in the `placement` section.
* To download the example application image, you must first accept the license agreement.
  * In a browser, navigate to https://container-registry.oracle.com/ and sign in.
  * Search for `example-todo` and `weblogic`.
  * For each one:
     * Select the image name in the results.
     * From the drop-down menu, select your language and click Continue.
     * Then read and accept the license agreement.

Set up the following environment variables to point to the kubeconfig file for the admin and managed clusters.
{{< clipboard >}}
<div class="highlight">

```
$ export KUBECONFIG_ADMIN=/path/to/your/adminclusterkubeconfig
$ export KUBECONFIG_MANAGED1=/path/to/your/managedclusterkubeconfig
```
</div>
{{< /clipboard >}}

**NOTE**: The ToDo List application deployment files are contained in the Verrazzano project located at
`<VERRAZZANO_HOME>/examples/multicluster/todo-list`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.


## Deploy the application

1. Create a namespace for the multicluster ToDo List example by applying the Verrazzano project file.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/todo-list/verrazzano-project.yaml >}}
   ```
</div>
{{< /clipboard >}}

1. Create a `docker-registry` secret to enable pulling the ToDo List example image from the registry.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN create secret docker-registry tododomain-repo-credentials \
           --docker-server=container-registry.oracle.com \
           --docker-username=YOUR_REGISTRY_USERNAME \
           --docker-password=YOUR_REGISTRY_PASSWORD \
           --docker-email=YOUR_REGISTRY_EMAIL \
           -n mc-todo-list
   ```

</div>
{{< /clipboard >}}

   Replace `YOUR_REGISTRY_USERNAME`, `YOUR_REGISTRY_PASSWORD`, and `YOUR_REGISTRY_EMAIL`
   with the values you use to access the registry.

1. Create and label secrets for the WebLogic domain:
{{< clipboard >}}
<div class="highlight">

   ```
   # Replace the values of the WLS_USERNAME and WLS_PASSWORD environment variables as appropriate.
   $ export WLS_USERNAME=<username>
   $ export WLS_PASSWORD=<password>
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN create secret generic tododomain-weblogic-credentials \
       --from-literal=password=$WLS_PASSWORD \
       --from-literal=username=$WLS_USERNAME \
       -n mc-todo-list

   $ kubectl --kubeconfig $KUBECONFIG_ADMIN create secret generic tododomain-jdbc-tododb \
       --from-literal=username=$WLS_USERNAME \
       --from-literal=password=$WLS_PASSWORD \
       -n mc-todo-list

   $ kubectl --kubeconfig $KUBECONFIG_ADMIN -n mc-todo-list label secret tododomain-jdbc-tododb weblogic.domainUID=tododomain
   ```

</div>
{{< /clipboard >}}

   Note that the ToDo List example application is preconfigured to use specific secret names.
   For the source code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).

1. Apply the component and multicluster application resources to deploy the ToDo List application.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/todo-list/todo-list-components.yaml >}}

   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/todo-list/mc-todo-list-application.yaml >}}
   ```

</div>
{{< /clipboard >}}

1. Wait for the ToDo List example application to be ready.
   The `tododomain-adminserver` pod may take several minutes to be created and `Ready`.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 wait pod \
       --for=condition=Ready tododomain-adminserver \
       -n mc-todo-list \
       --timeout=300s
   ```

</div>
{{< /clipboard >}}

1. Get the generated host name for the application.
{{< clipboard >}}
<div class="highlight">

   ```
   $ HOST=$(kubectl --kubeconfig $KUBECONFIG_MANAGED1 get gateway \
         -n mc-todo-list \
         -o jsonpath='{.items[0].spec.servers[0].hosts[0]}')
   $ echo $HOST

   # Sample output
   todo-appconf.mc-todo-list.11.22.33.44.nip.io
   ```

</div>
{{< /clipboard >}}

1. Get the `EXTERNAL_IP` address of the `istio-ingressgateway` service.
{{< clipboard >}}
<div class="highlight">

   ```
   $ ADDRESS=$(kubectl --kubeconfig $KUBECONFIG_MANAGED1 get service \
        -n istio-system istio-ingressgateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   $ echo $ADDRESS

   # Sample output
   11.22.33.44
   ```   

</div>
{{< /clipboard >}}

1. Access the ToDo List example application.

   * **Using the command line**
{{< clipboard >}}
<div class="highlight">

   ```
   # The expected response of this query is the HTML of a web page
   $ curl -sk https://${HOST}/todo/ \
       --resolve ${HOST}:443:${ADDRESS}
   ```

</div>
{{< /clipboard >}}
     If you are using `nip.io`, then you do not need to include `--resolve`.
   * **Local testing with a browser**

     Temporarily, modify the `/etc/hosts` file (on Mac or Linux)
     or `c:\Windows\System32\Drivers\etc\hosts` file (on Windows 10),
     to add an entry mapping the host name to the ingress gateway's `EXTERNAL-IP` address.
     For example:
     ```
     11.22.33.44 todo.example.com
     ```
     Then, you can access the application in a browser at `https://todo.example.com/todo`.
   * **Using your own DNS name**

      Point your own DNS name to the ingress gateway's `EXTERNAL-IP` address.

     * In this case, you would need to have edited the `todo-list-application.yaml` file
       to use the appropriate value under the `hosts` section (such as `yourhost.your.domain`),
       before deploying the ToDo List application.
     * Then, you can use a browser to access the application at `https://<yourhost.your.domain>/todo/`.

      Accessing the application in a browser will open a page, "Derek's ToDo List",
      with an edit field and an **Add** button that lets add tasks.

1. A variety of endpoints associated with
   the deployed ToDo List application are available to further explore the logs, metrics, and such.
   You can access them according to the directions [here]({{< relref "/docs/setup/access/#get-the-consoles-urls" >}}).

## Verify the deployed application

1. Verify that the application configuration, domain, and ingress trait all exist.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get ApplicationConfiguration -n mc-todo-list

   # Sample output
   NAME           AGE
   todo-appconf   19h

   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get Domain -n mc-todo-list

   # Sample output
   NAME          AGE
   todo-domain   19h

   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get IngressTrait -n mc-todo-list

   # Sample output
   NAME                           AGE
   todo-domain-trait-7cbd798c96   19h
   ```

</div>
{{< /clipboard >}}

1. Verify that the WebLogic Administration Server and MySQL pods have been created and are running.
   Note that this will take several minutes.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get pods -n mc-todo-list

   # Sample output
   NAME                     READY   STATUS    RESTARTS   AGE
   mysql-5c75c8b7f-vlhck    2/2     Running   0          19h
   tododomain-adminserver   4/4     Running   0          19h

   ```
</div>
{{< /clipboard >}}

## Undeploy the application

Regardless of its location, to undeploy the application,
delete the application resources and the project from the admin cluster.
Undeploy affects all clusters in which the application is located.

1. To undeploy the application, delete the ToDo List OAM resources.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
    -f {{< release_source_url raw=true path=examples/multicluster/todo-list/mc-todo-list-application.yaml >}}
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
    -f {{< release_source_url raw=true path=examples/multicluster/todo-list/todo-list-components.yaml >}}
   ```

</div>
{{< /clipboard >}}

1. Delete the project.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
    -f {{< release_source_url raw=true path=examples/multicluster/todo-list/verrazzano-project.yaml >}}
   ```

</div>
{{< /clipboard >}}

1. Delete the namespace `mc-todo-list` after the application pods are terminated. The secrets created for the WebLogic domain also will be deleted.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN delete namespace mc-todo-list
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 delete namespace mc-todo-list
   ```

</div>
{{< /clipboard >}}
