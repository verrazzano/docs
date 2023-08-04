---
title: "Spring Boot"
weight: 5
description: "A Spring Boot-based simple web application"
---

## Before you begin

Install Verrazzano by following the [installation]({{< relref "/docs/setup/install/installation.md" >}}) instructions.

**NOTE:** The Spring Boot example application deployment files are contained in the Verrazzano project located at `<VERRAZZANO_HOME>/examples/springboot-app`, where `VERRAZZANO_HOME` is the root of the Verrazzano project.


## Deploy the application

This example provides a simple web application developed using [Spring Boot](https://spring.io/guides/gs/spring-boot/). For more information and the source code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).

{{< alert title="NOTE" color="primary" >}}To run this application in the default namespace:
   ```
   $ kubectl label namespace default verrazzano-managed=true istio-injection=enabled
   ```
   If you chose the default namespace, you can skip Step 1 and ignore the `-n` option in the rest of the commands.
{{< /alert >}}

1. Create a namespace for the Spring Boot application and add a label identifying the namespace as managed by Verrazzano.
   ```
   $ kubectl create namespace springboot
   $ kubectl label namespace springboot verrazzano-managed=true istio-injection=enabled
   ```

1. To deploy the application, apply the Spring Boot OAM resources.
   ```
   $ kubectl apply -f {{< release_source_url raw=true path=examples/springboot-app/springboot-comp.yaml >}} -n springboot
   $ kubectl apply -f {{< release_source_url raw=true path=examples/springboot-app/springboot-app.yaml >}} -n springboot
   ```

1. Wait for the Spring Boot application to be ready.
   ```
   $ kubectl wait \
      --for=condition=Ready pods \
      --all \
      -n springboot \
      --timeout=300s
   ```

## Explore the application

1. Get the generated host name for the application.
   ```
   $ HOST=$(kubectl get gateways.networking.istio.io \
        -n springboot \
        -o jsonpath='{.items[0].spec.servers[0].hosts[0]}')
   $ echo $HOST

   # Sample output
   springboot-appconf.springboot.11.22.33.44.nip.io
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
     # The expected response of this query is the HTML of a web page
     $ curl -sk \
         https://${HOST} \
         --resolve ${HOST}:443:${ADDRESS}

     $ curl -sk \
         https://${HOST}/facts \
         --resolve ${HOST}:443:${ADDRESS}

     # Sample output
     In 1524, Verrazzano became the first European to enter the New York Harbor and the Hudson River.
     ```
     If you are using `nip.io`, then you do not need to include `--resolve`.
   * **Local testing with a browser**

     Temporarily, modify the `/etc/hosts` file (on Mac or Linux)
     or `c:\Windows\System32\Drivers\etc\hosts` file (on Windows 10),
     to add an entry mapping the host name to the ingress gateway's `EXTERNAL-IP` address.
     For example:
     ```
     11.22.33.44 springboot.example.com
     ```
     Then, you can access the application in a browser at `https://springboot.example.com/` and `https://springboot.example.com/facts`.

     - If you are using `nip.io`, then you can access the application in a browser using the `HOST` variable (for example, `https://${HOST}/facts`).  
     - If you are going through a proxy, you may need to add `*.nip.io` to the `NO_PROXY` list.

   * **Using your own DNS name**

     Point your own DNS name to the ingress gateway's `EXTERNAL-IP` address.

     * In this case, you would need to have edited the `springboot-app.yaml` file
       to use the appropriate value under the `hosts` section (such as `yourhost.your.domain`),
       before deploying the Spring Boot application.
     * Then, you can use a browser to access the application at `https://<yourhost.your.domain>/` and `https://<yourhost.your.domain>/facts`.

       The actuator endpoint is accessible under the path `/actuator` and the Prometheus endpoint exposing metrics data in a format that can be scraped by a Prometheus server is accessible under the path `/actuator/prometheus`.

1. A variety of endpoints associated with the deployed application are available to further explore the logs, metrics, and such.
You can access them according to the directions [here]({{< relref "/docs/access/#get-the-consoles-urls" >}}).

## Undeploy the application   

1. To undeploy the application, delete the Spring Boot OAM resources.
   ```
   $ kubectl delete -f {{< release_source_url raw=true path=examples/springboot-app/springboot-app.yaml >}} -n springboot
   $ kubectl delete -f {{< release_source_url raw=true path=examples/springboot-app/springboot-comp.yaml >}} -n springboot
   ```

1. Delete the namespace `springboot` after the application pod is terminated.
   ```
   $ kubectl delete namespace springboot
   ```
