---
title: "Search Log Records"
description: "Explore ways to search log records"
weight: 5
draft: false
---

To search Verrazzano logs, you can use the Oracle Cloud Infrastructure Console, Oracle Cloud Infrastructure CLI, or Oracle Cloud Infrastructure SDK.

For example, use the Oracle Cloud Infrastructure CLI to search the system logs for records emitted by the `verrazzano-application-operator` container:
{{< clipboard >}}
<div class="highlight">

```
$ oci logging-search search-logs --search-query=\
     "search \"ocid1.compartment.oc1..example/ocid1.loggroup.oc1.iad.example/ocid1.log.oc1.iad.example\" | \
     where \"data\".\"kubernetes.container_name\" = 'verrazzano-application-operator' | sort by datetime desc" \
     --time-start 2021-12-07 --time-end 2021-12-17
```

</div>
{{< /clipboard >}}

Search for all application log records in the `springboot` namespace:
{{< clipboard >}}
<div class="highlight">

```
$ oci logging-search search-logs --search-query=\
     "search \"ocid1.compartment.oc1..example/ocid1.loggroup.oc1.iad.example/ocid1.log.oc1.iad.example\" | \
     where \"data\".\"kubernetes.namespace_name\" = 'springboot' | sort by datetime desc" \
     --time-start 2021-12-07 --time-end 2021-12-17
```

</div>
{{< /clipboard >}}

For more information on searching logs, see the [Logging Query Language Specification](https://docs.oracle.com/en-us/iaas/Content/Logging/Reference/query_language_specification.htm).
