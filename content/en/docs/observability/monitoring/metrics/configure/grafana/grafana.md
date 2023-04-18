---
title: "Grafana"
linkTitle: Grafana
description: "Learn how to use Grafana to monitor Verrazzano"
weight: 3
draft: false
---

Grafana provides visualization for your Prometheus metric data.

- Single pod per cluster.
- Named `vmi-system-grafana-*` in the `verrazzano-system` namespace.
- Provides dashboards for metrics visualization.

To access Grafana:

1. Get the host name from the Grafana ingress.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get ingress vmi-system-grafana -n verrazzano-system

   # Sample output
   NAME                 CLASS    HOSTS                                              ADDRESS          PORTS     AGE
   vmi-system-grafana   <none>   grafana.vmi.system.default.123.456.789.10.nip.io   123.456.789.10   80, 443   26h
   ```

</div>
{{< /clipboard >}}


1. Get the password for the user `verrazzano`.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get secret \
       --namespace verrazzano-system verrazzano \
       -o jsonpath={.data.password} | base64 \
       --decode; echo
   ```

</div>
{{< /clipboard >}}

1. Access Grafana in a browser using the host name.
1. Log in using the `verrazzano` user and the password.

![Grafana](/docs/images/grafana-initial-page.png)


From here, you can select an existing dashboard or create a new dashboard.
To select an existing dashboard, use the drop-down list in the top left corner.
The initial value of this list is `Home`.


To view host level metrics, select `Host Metrics`. This will provide system metrics for all
of the nodes in your cluster.


To view the application metrics for the `todo-list` example application, select `WebLogic Server Dashboard`
because the `todo-list` application is a WebLogic application.

![WebLogicDashboard](/docs/images/grafana-weblogic-dashboard.png)

### Dashboard discovery

The Verrazzano Grafana instance supports dynamic dashboard discovery. This lets you deploy dashboards along with other application components.

Grafana will automatically discover dashboards in ConfigMaps that are labeled with `grafana_dashboard: "1"`. The ConfigMap must contain the dashboard JSON.
The ConfigMap may also be annotated with `k8s-sidecar-target-directory` to specify the name of a Grafana folder.

Here is an example ConfigMap.

```
apiVersion: v1
kind: ConfigMap
metadata:
  annotations:
    k8s-sidecar-target-directory: My App Dashboards
  labels:
    grafana_dashboard: "1"
  name: app-dashboard
  namespace: app
data:
  app_dashboard.json: |-
    {
      "title": "My App Dashboard",
      "uid": "Q4Bkkx",
      "version": 2,
      "panels": [
        {
          ...
        }
      ...
    }
```
