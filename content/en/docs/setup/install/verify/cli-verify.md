---
title: "Verify Using CLI"
description: "Verify installed Verrazzano using the `vz` CLI"
weight: 1
draft: false
---

To verify the Verrazzano installation, you can use the `vz status` command to determine the status of your installation.  After a successful installation, Verrazzano should be in the `Ready` state.

{{< clipboard >}}
```bash
$ vz status

# Sample output for a dev profile install
Verrazzano Status
  Name: example-verrazzano
  Namespace: default
  Profile: prod
  Version: v1.5.1
  State: Ready
  Available Components: 23/23
  Access Endpoints:
    consoleUrl: https://verrazzano.default.10.0.0.1.nip.io
    grafanaUrl: https://grafana.vmi.system.default.10.0.0.1.nip.io
    keyCloakUrl: https://keycloak.default.10.0.0.1.nip.io
    kialiUrl: https://kiali.vmi.system.default.10.0.0.1.nip.io
    openSearchDashboardsUrl: https://osd.vmi.system.default.10.0.0.1.nip.io
    openSearchUrl: https://opensearch.vmi.system.default.10.0.0.1.nip.io
    prometheusUrl: https://prometheus.vmi.system.default.10.0.0.1.nip.io
    rancherUrl: https://rancher.default.10.0.0.1.nip.io
```
{{< /clipboard >}}

For installation troubleshooting help, see the [Analysis Advice]({{< relref "/docs/troubleshooting/diagnostictools/analysisadvice/" >}}).

After the installation has completed, you can use the Verrazzano consoles.
For information on how to get the consoles URLs and credentials, see [Access Verrazzano]({{< relref "/docs/setup/access/" >}}).

## Next steps

(Optional) Run the example applications located [here]({{< relref "/docs/examples/_index.md" >}}).
