---
title: Keycloak Data Migration Failure
linkTitle: Keycloak Data Migration Failure
weight: 5
draft: false
---

### Summary
Analysis detected that the Verrazzano upgrade failed when migrating Keycloak data from the existing `legacyDB` to the new `InnoDB`.

### Steps
1. Verify whether the `dump-claim` PVC exists and is bound to the PV.
{{< clipboard >}}
<div class="highlight">

   ```
   $ k get pvc -n keycloak dump-claim

   # Sample Output
   NAME         STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
   dump-claim   Bound    pvc-c246d7c4-3041-4164-8c1e-744dda805686   2Gi        RWO            standard       12m
   ```
</div>
{{< /clipboard >}}
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get pv

   # Sample Output
   NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                 STORAGECLASS   REASON   AGE
   pvc-c246d7c4-3041-4164-8c1e-744dda805686   2Gi        RWO            Retain           Bound    keycloak/dump-claim   standard                49m
   ```
</div>
{{< /clipboard >}}

2. Get the `mysql-root password` from the `mysql` or `mysql-cluster-secret` secret in the `keycloak` namespace. The password is required to access the MySQL server as a `root` user in the following steps.
   {{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl get secret -n keycloak mysql -o jsonpath='{.data.mysql-root-password}' | base64 --decode

   # Sample Output
   lvYwPJjwFB
   ```
</div>
{{< /clipboard >}}

3. Create a `load-dump` pod to help in migrating the previous Keycloak database data into the new database instance.

    {{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl apply -f - <<EOF
     apiVersion: v1
     kind: Pod
     metadata:
       name: my-load-dump
       namespace: keycloak
       labels:
         job-name: load-dump
     spec:
       containers:
       - name: mysqlsh-load-dump
         image: ghcr.io/verrazzano/mysql-server:8.0.32
         volumeMounts:
         - mountPath: /var/lib/dump
           name: keycloak-dump
       volumes:
       - name: keycloak-dump
         persistentVolumeClaim:
           claimName: dump-claim
   EOF
   ```
</div>   
{{< /clipboard >}}

4. Start a shell session inside the pod, and then run these commands:
   {{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl exec -n keycloak my-load-dump -it -- /bin/bash
   ```

</div>
{{< /clipboard >}}
    a. Fix the `dump` directory permission.
      {{< clipboard >}}
<div class="highlight">

   ```
   $ chown -R 27:27 /var/lib/dump
   ```

</div>
{{< /clipboard >}}
    b. Check if the MySQL server is running. If it is not running, check if the MySQL pods in the `keycloak` namespace are ready, and then check again.
      {{< clipboard >}}
<div class="highlight">

   ```
   $ mysqladmin ping -h"mysql.keycloak.svc.cluster.local" -p{{ .RootPassword }}

   # Sample Output
   mysqld is alive
   ```

</div>
{{< /clipboard >}}
    c. Migrate the Keycloak data.
      {{< clipboard >}}
<div class="highlight">

   ```
   $ mysqlsh -u root -p{{ .RootPassword }} -h mysql.keycloak.svc.cluster.local -e 'util.loadDump("/var/lib/dump/dump", {includeSchemas: ["keycloak"], includeUsers: ["keycloak"], loadUsers: true})'

   ```

</div>
{{< /clipboard >}}


      ```
      # Sample Output
      Loading DDL, Data and Users from '/var/lib/dump/dump' using 4 threads.
      Opening dump...
      Target is MySQL 8.0.32. Dump was produced from MySQL 8.0.29
      Scanning metadata - done       
      Checking for pre-existing objects...
      Executing common preamble SQL
      Executing DDL - done         
      Executing user accounts SQL...
      NOTE: Skipping CREATE/ALTER USER statements for user 'root'@'%'
      NOTE: Skipping CREATE/ALTER USER statements for user 'root'@'localhost'
      NOTE: Skipping GRANT statements for user 'root'@'%'
      NOTE: Skipping GRANT statements for user 'root'@'localhost'
      Executing view DDL - done       
      Starting data load
      4 thds loading \ 100% (159.79 KB / 159.79 KB), 0.00 B/s, 33 / 93 tables done
      Recreating indexes - done       
      Executing common postamble SQL                                              
      93 chunks (1.31K rows, 159.79 KB) for 93 tables in 1 schemas were loaded in 3 sec (avg throughput 159.79 KB/s)
      0 warnings were reported during the load.
      ```


5. In the `db-migration` secret, add a `db-migrated` field and set its value to `true (base64 encoded)`. This will notify the Verrazzano platform operator that the Keycloak data was migrated manually.
   {{< clipboard >}}
<div class="highlight">

   ```
   $ k edit secret -n keycloak db-migration

   # Sample Output
   data:
     db-migrated: dHJ1ZQ==        # true base64 encoded is dHJ1ZQ==
     database-dumped: dHJ1ZQ==
     deployment-found: dHJ1ZQ==
     ...
   ```

</div>
{{< /clipboard >}}

6. Delete the `load-dump` pod.
      {{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl delete pod -n keycloak my-load-dump
   ```

</div>
{{< /clipboard >}}

### Related information
* [Platform Setup]({{< relref "/docs/setup/install/prepare/platforms/_index.md" >}})
* [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug/)
* [MySQL Troubleshooting](https://dev.mysql.com/doc/refman/8.0/en/starting-server-troubleshooting.html)
