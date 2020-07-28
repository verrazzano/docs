---
title: "Install Verrazzano Components"
weight: 4
---

# Install Verrazzano Components

The following Verrazzano components need to be installed in the management cluster:

* Verrazzano custom resource definitions, operators, and admission controllers
* Verrazzano web user interface
* Verrazzano Monitoring Infrastructure
* NGINX ingress controller

These components are installed using the provided Helm charts using the steps below:

* As per the prerequisites, ensure that you have Helm 3.1 or later.  You can check using
  this command:

   ```bash
   helm version
   ```

* Add a reference to the Verrazzano Helm repository:

    ```bash
    helm repo add verrazzano https://github.com/oracle/verrazzano-helm-charts
    ```

    {{< hint danger >}}
**TODO**  
Update with final/correct repository address.  Pre-release address is:
https://objectstorage.us-phoenix-1.oraclecloud.com/n/stevengreenberginc/b/verrazzano-helm-chart/o/XXX
where `XXX` is the version number, for example `0.113`.
    {{< /hint >}}

* Update the Helm repositories using this command:

    ```bash
    helm repo update
    ````

* Install the Verrazzano Helm release with the following command:

    ```bash
    helm install \
      verrazzano \ {{< linenum 1 >}}
      verrazzano \ {{< linenum 2 >}}
      --namespace verrazzano \ {{< linenum 3 >}}
      --set config.envName=development \ {{< linenum 4 >}}
      --set config.dnsSuffix=your.domain.com \ {{< linenum 5 >}}
      --set rancherOperator.rancherURL=https://rancher.cattle-system.svc \ {{< linenum 6 >}}
      --set rancherOperator.rancherUserName=rancher \ {{< linenum 7 >}}
      --set rancherOperator.rancherPassword=welcome1 \ {{< linenum 8 >}}
      --set rancherOperator.rancherHostname=0.0.0.0 \ {{< linenum 9 >}}
      --set verrazzanoAdmissionController.caBundle="-----BEGIN CERTIFICATE-----
    MIIC0DCCAbigAwIBAgIBADANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDEw5zZXJ2
    ZXItY2VydC1jYTAeFw0yMDA0MTAxNzEyMTVaFw0zMDA0MDgxNzEyMTVaMBkxFzAV
    BgNVBAMTDnNlcnZlci1jZXJ0LWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
    CgKCAQEA56dL/R7kGdNa7zKl02BcVuVT4hNvk8qq0rxVYndN0hDSiG7pItPnMKWx
    4ZWfrB1/nztdmkOqLxpr+CfaA0SdpY6yxWXdEhlNkfr7gRDlmmaOkyLsLHT4S9Aw
    4EgSRgEYMTGiE1w+dk7kSi0OaU7YgBk+jh/MfwhBkAIi7UukyvnWc3Ky+sKa09Mr
    gHakj9C9DUDj2+Q1/9x89zxNDMy9LhvNYT4RSgOoduuX+Dlmx15lxomq1kf/xagT
    MpmLIv68D2M4kyYiAPt+vHGshtamB7pBuX3lB+zhmRBLX6CoM3zVd54UmKLyoDtN
    3mjlq3QmkK5lGI3IbWceZrkFMdlnAQIDAQABoyMwITAOBgNVHQ8BAf8EBAMCAqQw
    DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAY8hABE2/IT/3Qp8P
    a3y6op/WLWTh7rvSaVO/pTH1oW7sWhobsFzosmvEhxuE/haX40E2cad4bwYS8mCk
    uyxSwMJOvDClh4Yl9THN462ux8s9nvvjsrEzJSpIVW13WdRRW99ZwL122eRmOECH
    LcEPf0BjVu3wZvfe3MqqlVJXbDuCicveruGn4eek7zAVBndPcEWhvS/idRMlq0Xw
    ONWRoNUlFjQOUUjolGt9gKRJSZyu/+5mqO1J1Y0QxX70VuqVRaZXi13srqornBs+
    cTJPEHjB4ZvO/SgU5NuAvacPA3e89Y1NOj7oqO+X0uA3iUcSp6CrqR8SYwwtQrt0
    8MirUQ==
    -----END CERTIFICATE-----"
    ````

    {{< hint danger >}}
**TODO**  
Need to get rid of that cert.  
Check if external-dns and cert-manager are included in these charts,
and if so, add config for them.
    {{< /hint >}}

    {{< linenumref 1 >}} This is the name of the Helm release.  
    {{< linenumref 2 >}} This is the name of the Helm chart, which is used to
    find the right chart in the configured repositories.  
    {{< linenumref 3 >}} Verrazzano components must be installed into a
    namespace called `verrazzano`.  
    {{< linenumref 4 >}} This sets the name of your Verrazzano environment.
    Together with the `dnsSuffix` on the next line, this determines what
    the fully qualified names of your various endpoints will be.  In this
    example, your endpoints would be named `https://service.development.your.domain.com`
    where `service` would be the actual endpoint name, like `rancher` or `console`.   
    {{< linenumref 5 >}} This is the domain name used to name your endpoints.  
    {{< linenumref 6 >}} This is the address (within the management cluster) of the
    Racnher server that was installed in an earlier step.    
    {{< linenumref 7 >}} This is the user name to access Rancher server.    
    {{< linenumref 8 >}} This is the password to access Rancher server.    
    {{< linenumref 9 >}} This is the listen address of the Rancher server.  

* Next step here.

More stuff here.
