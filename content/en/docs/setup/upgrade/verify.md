---
title: "Verify the Upgrade"
description: ""
weight: 3
draft: false
---

To see detailed progress of the upgrade, view the logs with the following command.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l app=verrazzano-platform-operator \
    -o jsonpath="{.items[0].metadata.name}") | grep '^{.*}$' \
    | jq -r '."@timestamp" as $timestamp | "\($timestamp) \(.level) \(.message)"'
```
</div>
{{< /clipboard >}}

Check that all the pods in the `verrazzano-system` namespace are in the `Running` state.  While the upgrade is in progress,
you may see some pods terminating and restarting as newer versions of components are applied, for example:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get pods -n verrazzano-system

# Sample output
coherence-operator-866798c99d-r69xt                1/1     Running   1          43m
fluentd-f9fbv                                      2/2     Running   0          38m
fluentd-n79c4                                      2/2     Running   0          38m
fluentd-xslzw                                      2/2     Running   0          38m
oam-kubernetes-runtime-56cdb56c98-wn2mb            1/1     Running   0          43m
verrazzano-application-operator-7c95ddd5b5-7xzmn   1/1     Running   0          42m
verrazzano-authproxy-594d8c8dcd-llmlr              2/2     Running   0          38m
verrazzano-console-74dbf97fdf-zxvvn                2/2     Running   0          38m
verrazzano-monitoring-operator-6fcf8484fd-gfkhs    1/1     Running   0          38m
verrazzano-operator-66c8566f95-8lbs6               1/1     Running   0          38m
vmi-system-grafana-799d79648d-wsdp4                2/2     Running   0          38m
vmi-system-kiali-574c6dd94d-f49jv                  2/2     Running   0          41m
weblogic-operator-7b447fdb47-wlw64                 2/2     Running   0          42m
```
</div>
{{< /clipboard >}}

Check that the pods in your application namespaces are ready, for example:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get pods -n todo-list

# Sample output
NAME                     READY   STATUS    RESTARTS   AGE
mysql-67575d8954-d4vkm   2/2     Running   0          39h
tododomain-adminserver   4/4     Running   0          39h
```
</div>
{{< /clipboard >}}
