---
title: "ToDo List"
weight: 6
description: "An example application containing a WebLogic component"
---

## Before you begin

* Install Verrazzano by following the [installation]({{< relref "/docs/setup/install/installation.md" >}}) instructions.
* To download the example image, you must first accept the license agreement.
  * In a browser, navigate to https://container-registry.oracle.com/ and sign in.
  * Search for `example-todo` and `weblogic`.
  * For each one:
     * Select the image name in the results.
     * From the drop-down menu, select your language and click Continue.
     * Then read and accept the license agreement.

**NOTE:** The ToDo List example application deployment files are contained in the Verrazzano project located at
`<VERRAZZANO_HOME>/examples/todo-list`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.

All files and paths in this document are relative to `<VERRAZZANO_HOME>/examples/todo-list`.

## Deploy the ToDo List application

ToDo List is an example application containing a WebLogic component.
For more information and the source code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).

{{< alert title="NOTE" color="primary" >}}To run this application in the default namespace:
   ```
   $kubectl label namespace default verrazzano-managed=true istio-injection=enabled
   ```
   If you chose the default namespace, you can skip Step 1. and ignore the `-n` option in the rest of the commands.
{{< /alert >}}

1. Create a namespace for the ToDo List example and add a label identifying the namespace as managed by Verrazzano.
   ```
   $ kubectl create namespace todo-list
   $ kubectl label namespace todo-list verrazzano-managed=true istio-injection=enabled
   ```

1. Create a `docker-registry` secret to enable pulling the ToDo List example image from the registry.
   ```
   $ kubectl create secret docker-registry tododomain-repo-credentials \
           --docker-server=container-registry.oracle.com \
           --docker-username=YOUR_REGISTRY_USERNAME \
           --docker-password=YOUR_REGISTRY_PASSWORD \
           --docker-email=YOUR_REGISTRY_EMAIL \
           -n todo-list
   ```

   Replace `YOUR_REGISTRY_USERNAME`, `YOUR_REGISTRY_PASSWORD`, and `YOUR_REGISTRY_EMAIL`
   with the values you use to access the registry.  

1. Create and label secrets for the WebLogic domain:
   ```
   # Replace the values of the WLS_USERNAME and WLS_PASSWORD environment variables as appropriate.
   $ export WLS_USERNAME=<username>
   $ export WLS_PASSWORD=<password>
   $ kubectl create secret generic tododomain-weblogic-credentials \
       --from-literal=password=$WLS_PASSWORD \
       --from-literal=username=$WLS_USERNAME \
       -n todo-list

   $ kubectl create secret generic tododomain-jdbc-tododb \
       --from-literal=username=$WLS_USERNAME \
       --from-literal=password=$WLS_PASSWORD \
       -n todo-list

   $ kubectl -n todo-list label secret tododomain-jdbc-tododb weblogic.domainUID=tododomain
   ```

   Note that the ToDo List example application is preconfigured to use specific secret names.
   For the source code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).  

1. To deploy the application, apply the example resources.
   ```
   $ kubectl apply -f {{< release_source_url raw=true path=examples/todo-list/todo-list-components.yaml >}} -n todo-list
   $ kubectl apply -f {{< release_source_url raw=true path=examples/todo-list/todo-list-application.yaml >}} -n todo-list
   ```

1. Wait for the ToDo List application to be ready. You can monitor its progress by listing pods and inspecting the output, or
you can use the `kubectl wait` command. You may need to repeat the `kubectl wait` command several times before it is successful.
   The `tododomain-adminserver` pod may take a while to be created and `Ready`.
   ```
   $ kubectl get pods -n todo-list

   # -or- #

   $ kubectl wait pod \
      --for=condition=Ready tododomain-adminserver \
      -n todo-list
   ```

1. Get the generated host name for the application.
   ```
   $ HOST=$(kubectl get gateway \
        -n todo-list \
        -o jsonpath='{.items[0].spec.servers[0].hosts[0]}')
   $ echo $HOST

   # Sample output
   todo-appconf.todo-list.10.11.12.13.nip.io
   ```

1. Get the `EXTERNAL_IP` address of the `istio-ingressgateway` service.
   ```
   $ ADDRESS=$(kubectl get service \
        -n istio-system istio-ingressgateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   $ echo $ADDRESS

   # Sample output
   10.11.12.13
   ```   

1. Access the ToDo List application:

   * **Using the command line**
     ```
     # The expected response of this query is the HTML of a web page
     $ curl -sk \
        https://${HOST}/todo/ \
        --resolve ${HOST}:443:${ADDRESS}
     ```
     If you are using `nip.io`, then you do not need to include `--resolve`.
   * **Local testing with a browser**

     Temporarily, modify the `/etc/hosts` file (on Mac or Linux)
     or `c:\Windows\System32\Drivers\etc\hosts` file (on Windows 10),
     to add an entry mapping the host name to the ingress gateway's `EXTERNAL-IP` address.
     For example:
     ```
     10.11.12.13 todo.example.com
     ```
     Then, you can access the application in a browser at `https://todo.example.com/todo`.

     If you are using `nip.io`, then you can access the application in a browser using the `HOST` variable (for example, `https://${HOST}/todo`).  If you are going through a proxy, then you may need to add `*.nip.io` to the `NO_PROXY` list.

   * **Using your own DNS name**
     * Point your own DNS name to the ingress gateway's `EXTERNAL-IP` address.
     * In this case, you would need to have edited the `todo-list-application.yaml` file
       to use the appropriate value under the `hosts` section (such as `yourhost.your.domain`),
       before deploying the ToDo List application.
     * Then, you can use a browser to access the application at `https://<yourhost.your.domain>/todo/`.

       Accessing the application in a browser opens the page, "Derek's ToDo List",
       with an edit field and an **Add** button that lets you add tasks.

1. A variety of endpoints associated with the deployed ToDo List application, are available to further explore the logs, metrics, and such.
   You can access them according to the directions [here]({{< relref "/docs/operations/#get-the-consoles-urls" >}}).

## Access the WebLogic Server Administration Console

To access the Console from the machine where you are running `kubectl`:

1. Set up port forwarding.
   ```
   $ kubectl port-forward pods/tododomain-adminserver 7001:7001 -n todo-list
   ```
   **NOTE**: If you are using the OCI Cloud Shell to run `kubectl`, in order to access the Console using port forwarding, you will need to run `kubectl` on another machine.

1. Access the WebLogic Server Administration Console from your browser.
   ```
   http://localhost:7001/console
   ```

{{< alert title="NOTE" color="warning" >}}
It is recommended that the WebLogic Server Administration Console _not_ be exposed publicly.
{{< /alert >}}

## Troubleshooting

1. Verify that the application configuration, domain, and ingress trait all exist.
   ```
   $ kubectl get ApplicationConfiguration -n todo-list

   # Sample output
   NAME           AGE
   todo-appconf   19h

   $ kubectl get Domain -n todo-list

   # Sample output
   NAME          AGE
   todo-domain   19h

   $ kubectl get IngressTrait -n todo-list

   # Sample output
   NAME                           AGE
   todo-domain-trait-7cbd798c96   19h
   ```

1. Verify that the WebLogic Administration Server and MySQL pods have been created and are running.
   Note that this will take several minutes.
   ```
   $ kubectl get pods -n todo-list

   # Sample output
   NAME                     READY   STATUS    RESTARTS   AGE
   mysql-5c75c8b7f-vlhck    2/2     Running   0          19h
   tododomain-adminserver   4/4     Running   0          19h
   ```
## Undeploy the application

1. To undeploy the application, delete the ToDo List OAM resources.
   ```
   $ kubectl delete -f {{< release_source_url raw=true path=examples/todo-list/todo-list-application.yaml >}} -n todo-list
   $ kubectl delete -f {{< release_source_url raw=true path=examples/todo-list/todo-list-components.yaml >}} -n todo-list
   ```

1. Delete the namespace `todo-list` after the application pods are terminated. The secrets created for the WebLogic domain also will be deleted.
   ```
   $ kubectl delete namespace todo-list
   ```
