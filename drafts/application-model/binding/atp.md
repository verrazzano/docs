---
title: "ATP"
weight: 3
bookHidden: true
---

## Autonomous Transaction Processing


Constraints:

* Binding DB name must be unique within a region in a tenancy 
* Binding DB SID name in binding file must match JDBC db name in bobs-bookstore-topology.yaml file connect string and other places where db name is being used.


# Configuring ATP Databases in Verrazzano
Provisioning of ATP databases in Verrazzano is enabled by configuring ATP attributes in `atpBinding` section in `VerrazzanoBinding` and corresponding `connection` in WebLogic/Helidon app sections of `VerrazzanoModel`. The credentials and connection details for the ATP are provisioned as Kubernetes secrets in the cluster.

```
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoBinding
metadata:
  name: bobs-books-binding
  namespace: default
spec:
  name: "Bobs Books"
  description: "Bob's Books binding"
  [...]
  placement:
    - name: oow5-demo-2
      namespaces:
        - name: bob
          components:
            - name: bobs-bookstore
            - name: books
  [...]          
  atpBindings:
    - name: "books"
      compartmentId: "<compartment_id_to_create_atp_instances_in>"
      password:
        secretKeyRef:
           name: atpsecret
           key: password
      walletPassword:
        secretKeyRef:
           name: atpsecret
           key: walletPassword
```

```
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoModel
metadata:
  name: bobs-books-model
  namespace: default
spec:
  name: bobs-books
  version: "1.0"
  description: "Bob's Books model"
  scope: Namespaced
  group: verrazzano.io
  weblogicDomains:
  [...]
    - name: bobs-bookstore
      [...]
      connections:
        [...]
        - atp:
            - target: books  
```

## OCI Credentials
ATP provisioning requires OCI credentials and these are required to be created as a secret in the kubernetes cluster.

```bash
kubectl create secret generic ocicredentials
--from-literal=tenancy=<TENANCY_OCID>
--from-literal=user=<USER_OCID>
--from-literal=fingerprint=<USER_PUBLIC_API_KEY_FINGERPRINT>
--from-literal=region=<USER_OCI_REGION>
--from-literal=passphrase=<PASSPHRASE_STRING>
--from-file=privatekey=<PATH_OF_USER_PRIVATE_API_KEY>`
```

By default the secret should be created in default namespace. If we need to create this secret in a different namespace and with a different name other than `ocicredentials` - then the `verrazzano-oci-db-operator` deployment must be edited to pass the changed values as environment variables.

```bash
- name: OCI_CREDENTIALS_SECRET_NAMESPACE
  value: "secret-house"
- name: OCI_CREDENTIALS_SECRET_NAME
  value: "oci-secret" 
```


## ATP attributes
Following is the list of attributes that can be configured for an ATP instance

 Name | Description | Optional | Default Value 
 ---|---|---|--- 
 `name` | Display Name of the ATP in OCI. | No | 
 `dbName` | Name of database instance for the ATP instance .<br/> **Note:** The same database name cannot be used for multiple Autonomous Databases in the same tenancy in the same region. | Yes | Same as `name`
 `compartmentId` | The OCID of the compartment in which the ATP DB exists/is to be provisioned | No | 
 `cpuCount` | Number of ATP CPUs | Yes | `1` 
 `storageSizeTBs` | ATP storage size in TB | Yes | `1` 
 `licenseType` | ATP license type (NEW or BYOL) | Yes | `BYOL` 
 `walletSecret` | Name of the Kubernetes secret that contains/will contain the ATP wallet | Yes | `name` with `-wallet` appended 
 `walletPassphraseSecret` | Name of the Kubernetes secret that contains/will contain the passphrase for the ATP wallet and as well as the admin password for Database. Passwords are kept in a double base64 encoded format in the secret. | Yes | `name` with `-passphrase` appended
 `password` | Password for admin user of ATP Database, provided as a `SecretKeyRef` | No |  
 `walletPassword` | Password for ATP Wallet, provided as a `SecretKeyRef` | No | 
 `useExisting` | Whether to use an existing ATP with same database name as `dbName` from same compartment | Yes | `false`
  `isAutoScalingEnabled` | Whether AutoScaling needs to be enabled, if ATP exists on shared Exadata Infrastructure | Yes | `false`
 `whitelistedIps` | List of ip/vcn ocid to be whitelisted, if ATP exists on shared Exadata Infrastructure | Yes | `[]`

## ATP secrets
The operator creates two types of secrets for accessing the provisioned ATP.

User secret: Contains the passphrase for the ATP wallet and as well as the admin password for Database. Passwords are kept in a double base64 encoded format in the secret. If no `UserSecretName` was specified while provisioning the ATP, by default secret is created with `name` with `-wallet` appended.

Wallet secret: Contains base64 encoded contents of 

* tnsnames.ora and sqlnet.ora: Network configuration files storing connect descriptors and SQL*Net client side configuration.
* cwallet.sso and ewallet.p12: Auto-open SSO wallet and PKCS12 file. PKCS12 file is protected by the decoded value of password provided in `walletPassword`
* keystore.jks and truststore.jks: Java keystore and truststore files. They are protected by the decoded value of password provided in `walletPassword`

## ATP Status
Following Status fields are updated by the operator on ATP CR.

Name | Description
 ---|---
`walletSecret` | Name of the secret containing ATP wallet
`userSecret` | Name of the secret containing password for database and wallet
`state` | Lifecycle state of ATP
`status` | Status of provisioning/deprovisioning
`isFailed` | true if provisioning fails
`timestamp` | Timestamp of status
`ocid` | Ocid of ATP provisioned  



## ATP passwords
The `password` and `walletPassword` attributes can only be populated from a secret present in the kubernetes cluster. For example - to use `s12345678910` as `password` and `Welcome_1234` as the `walletPassword` create a secret like

```bash
kubectl create secret generic atpsecret \
--from-literal=password=s12345678910S \
--from-literal=walletPassword=Welcome_1234
```

and update the name of the secret and key for password and walletPassword in the atpBinding

```
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoBinding
metadata:
  name: bobs-books-binding
  namespace: default
spec:
  [...]          
  atpBindings:
    - name: "books"
      compartmentId: "<compartment_id_to_create_atp_instances_in>"
      password:
        secretKeyRef:
           name: atpsecret
           key: password
      walletPassword:
        secretKeyRef:
           name: atpsecret
           key: walletPassword
```

To update existing admin or wallet password, we must either create a new secret or add the password(s) as different keys in the existing secret. For example, to change `password` to `s12345678911S` - create a new secret

```bash
kubectl create secret generic atpsecret1 \
--from-literal=password=s12345678911S \
```

and update the resource with new secret name

```
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoBinding
metadata:
  name: bobs-books-binding
  namespace: default
spec:
  [...]          
  atpBindings:
    - name: "books"
      compartmentId: "<compartment_id_to_create_atp_instances_in>"
      password:
        secretKeyRef:
           name: atpsecret1
           key: password
           [...]
```


### Unique ATP Database name per tenancy
The ATP Database Name needs to be unique per tenancy in OCI as mentioned [here](https://docs.oracle.com/en/cloud/paas/atp-cloud/atpud/clone-adb.html#GUID-B405F5F1-39E5-43AE-AFE0-99467E753487). Therefore a value for `name` attribute once used for an `atpBinding` can not be reused to create another `atpBinding` in the same compartment. This also means that if for some reason there will already exist another ATP instance with same name in that compartment when we apply the binding, it is bound to fail..

## How to use ATP databases in Verrazzano applications
The Kubernetes secrets created for the ATP Instance (the `walletSecret` and `walletPassphraseSecret`) can be mounted and used in the application pods that want to use ATP. See example in `superdomain/demo-model.yaml` where the `bobs-bookstore` WebLogic domain is using ATP database `books`.

```
weblogicDomains:
  [...]
  - name: bobs-bookstore
    [...]
    domainCRValues:
      [...]
      serverPod:
        [..]
        volumes:
            # Mount the ATP secret specified by walletSecret in atp binding(here the value is books-wallet). 
            # This will contain base64 encoded contents of 
            #
            # tnsnames.ora and sqlnet.ora: Network configuration files storing connect 
            # descriptors and SQL*Net client side configuration.
            #
            # cwallet.sso and ewallet.p12: Auto-open SSO wallet and PKCS12 file. PKCS12 file 
            # is protected by the decoded value of password provided in walletPassword.
            #
            # keystore.jks and truststore.jks: Java keystore and truststore files. They are 
            # protected by the decoded value of password provided in walletPassword.
            #
            # ojdbc.properties: Contains the wallet related connection property required for 
            # JDBC connection
            - name: creds-raw
              secret:
                secretName: books-wallet
            # Mount an emptyDir as a placeholder for decoded files
            - name: creds
              emptyDir: {}
        [...]
        volumeMounts:
            # This volume mount will act as TNS_ADMIN for all the containers in the pod and 
            # as well as will contain the wallets and jks
            - name: creds
              mountPath: /db/wallet
        initContainers:
            # An initContainer to base64 decode contents from the creds-raw volume and place 
            # the resulting files in creds volume. Also this container replaces the placeholder 
            # path of wallet (?/network/admin) in sqlnet.ora to /db/wallet which is actual path 
            # of wallet in pod
            - name: decode-creds
            [...]
            # Another initContainer to use both the base64 decoded files (as a result of decode-creds)from 
            # /db/wallet mount and as well the database password (as the base64 decoded value of 
            # password) present in the secret specified by walletPassphraseSecret (here the secret 
            #  name is books-passphrase)
            - name: create-schema
              env:
              # TNS_ADMIN env variable should be present in order for sqlplus to resolve service name
              - name: TNS_ADMIN
                value: "/db/wallet"
              - name: DB_ADMIN_USER
                valueFrom:
                  secretKeyRef:
                    name: books-wallet
                    key: user_name
              # Read password from books-passphrase secret
              - name: DB_ADMIN_PWD
                valueFrom:
                  secretKeyRef:
                    name: books-passphrase
                    key: password 
              # Capture schema creation SQL in an env variable 
              - name: SQL
                value: |  
                [...]
              command:
              - bash
              - -c
              # Double base64 decode the password contained in books-passphrase
              # Dump the SQL env variable to a file and run in SQLPlus
              - "DB_ADMIN_PWD_DECODED=`echo $DB_ADMIN_PWD | base64 --decode | base64 --decode`; 
                 DB_ADMIN_USER_LOWER=${DB_ADMIN_USER,,}; 
                 echo \"$SQL\">/tmp/run.sql; 
                 COMMAND=\"sqlplus $DB_ADMIN_USER_LOWER/$DB_ADMIN_PWD_DECODED@books_high@/tmp/run.sql\";
                 eval $COMMAND"                      

```

## Configuration for WebLogic domains to use ATP in Verrazzano
The demo application uses [WDT](https://github.com/oracle/weblogic-deploy-tooling) to create WebLogic domain
in the docker image for bobs-bookstore. The WDT requires specifying the model for the domain in a yaml. The model for bobs-bookstore is specified in `bobs-bookstore-order-manager/deploy/bobs-bookstore-topology.yaml`.
These application images are mostly created during the *build* stage of applications and hence any information required to create an domain must be specified in the model *before* it can be deployed to a cluster.

The DataSource configuration for the domain is present in the `resources/JDBCSystemResource` section. More details on how ATP can be used with WebLogic domains can be found [here](https://weblogic.cafe/posts/atp-datasource/).

```
resources:
  JDBCSystemResource:
    books:
      Target: 'cluster-1'
      JdbcResource:
        JDBCDataSourceParams:
          JNDIName: [
            jdbc/books
          ]
        JDBCDriverParams:
          DriverName: io.opentracing.contrib.jdbc.TracingDriver
          URL : 'jdbc:tracing:oracle:thin:@books_high'
          PasswordEncrypted: '@@PROP:db.password@@'
          Properties:
            user:
              Value: admin
            oracle.net.tns_admin:
              Value: "/db/wallet"
            oracle.net.ssl_version:
              Value: "1.2"
            javax.net.ssl.trustStore:
              Value: "/db/wallet/truststore.jks"
            oracle.net.ssl_server_dn_match:
              Value: true
            javax.net.ssl.keyStoreType:
              Value: JKS
            javax.net.ssl.trustStoreType:
              Value: JKS
            javax.net.ssl.keyStore:
              Value: "/db/wallet/keystore.jks"
            javax.net.ssl.keyStorePassword:
              Value: '@@PROP:wallet.password@@'
            javax.net.ssl.trustStorePassword:
              Value: '@@PROP:wallet.password@@'
            oracle.jdbc.fanEnabled:
              Value: false
```

The parameters @@PROP:db.password@@ and @@PROP:wallet.password@@ represent the placeholders for actual database and wallet passwords. (For more information about this notation see [WDT Variable Injection](https://github.com/oracle/weblogic-deploy-tooling/blob/master/site/variable_injection.md) feature)

The base64 encode value of these properties are specified in `bobs-bookstore-order-manager/deploy/properties/docker-build/bobs-bookstore-topology.properties.encoded`. The build script present at `bobs-bookstore-order-manager/deploy/build.sh` is responsible for decoding these properties at the time of build and creating another property file with decoded values. This decoded property file is what being passed to the WDT [createDomain](https://github.com/oracle/weblogic-deploy-tooling/blob/master/site/create.md) tool to create the actual domain with decoded values in Dockerfile.

It should be noted that value for `wallet.password` in `bobs-bookstore-topology.properties.encoded` is same as value for `walletPassword` (i.e. Base64 encoded value for `Welcome_1234`) and value for `db.password` is same as default value for `password` (which is Base64 encoded value for `s12345678910S`) in `atp-secret` used as placeholder for atp secrets. 

### Using non default passwords for ATP admin user or wallet
If you intend to use a different password for the ATP admin user or wallet by updating the 
secret or creating new atp secret in `atpBinding` section - same values should be updated in the `bobs-bookstore-topology.properties.encoded` file and the image will have to be rebuilt and redeployed.

### Using non default ATP Database name
The example application uses default database name as `books`. In a situation that an ATP database with same name already exists in the OCI tenancy, the ATP database name and its references must be changed in model/binding and other relevant files given the restriction described [earlier](#unique-atp-database-name-per-tenancy). Following changes will need to be made to use a different name for the ATP database:

## Changes in binding file (`demo-binding.yaml`)
Change the ATP component name (say to `bookstore`) in `atpBinding` and `placement` section
```
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoBinding
metadata:
  name: bobs-books-binding
  namespace: default
spec:
  name: "Bobs Books"
  description: "Bob's Books binding"
  [...]
  placement:
    - name: oow5-demo-2
      namespaces:
        - name: bob
          components:
            - name: bobs-bookstore
            - name: bookstore
  [...]          
  atpBindings:
    - name: "bookstore"
```

## Changes in WDT model file (`bobs-bookstore-order-manager/deploy/bobs-bookstore-topology.yaml`)
The `URL` in `JDBCDriverParams` specified in [WDT model](#configuration-for-weblogic-domains-to-use-atp-in-verrazzano) contains the actual service name of the database (`books_high`).

```
URL : 'jdbc:tracing:oracle:thin:@books_high'
```

The service name is derived from the `name` attribute in `atpBinding` which is `books` by default. Since we intend to use a different name for your ATP database - different service name will be assigned to the database and the same needs to be update in WDT model as well.

```
resources:
  JDBCSystemResource:
    books:
      Target: 'cluster-1'
      JdbcResource:
        JDBCDataSourceParams:
          JNDIName: [
            jdbc/books
          ]
        JDBCDriverParams:
          DriverName: io.opentracing.contrib.jdbc.TracingDriver
          URL : 'jdbc:tracing:oracle:thin:@bookstore_high'
          PasswordEncrypted: '@@PROP:db.password@@'
          Properties:
            user:
              Value: admin
            oracle.net.tns_admin:
              Value: "/db/wallet"
            oracle.net.ssl_version:
              Value: "1.2"
            javax.net.ssl.trustStore:
              Value: "/db/wallet/truststore.jks"
            oracle.net.ssl_server_dn_match:
              Value: true
            javax.net.ssl.keyStoreType:
              Value: JKS
            javax.net.ssl.trustStoreType:
              Value: JKS
            javax.net.ssl.keyStore:
              Value: "/db/wallet/keystore.jks"
            javax.net.ssl.keyStorePassword:
              Value: '@@PROP:wallet.password@@'
            javax.net.ssl.trustStorePassword:
              Value: '@@PROP:wallet.password@@'
            oracle.jdbc.fanEnabled:
              Value: false
```
Remember that any changes to WDT model require recreating the domain and hence the docker image followed by redeployment in the cluster. 

## Changes in model file (`demo-model.yaml`)
Change the ATP connection target (say to `bookstore`) in `connections`
```
apiVersion: verrazzano.io/v1beta1
kind: VerrazzanoModel
metadata:
  name: bobs-books-model
  namespace: default
spec:
  name: bobs-books
  version: "1.0"
  description: "Bob's Books model"
  scope: Namespaced
  group: verrazzano.io
  weblogicDomains:
  [...]
    - name: bobs-bookstore
      [...]
      connections:
        [...]
        - atp:
            - target: bookstore  
```

Also any other references to the actual service name (such that in connectionString specified in command for `create-schema` initContainer) in model will also need to be changed.

```
COMMAND=\"sqlplus $DB_ADMIN_USER_LOWER/$DB_ADMIN_PWD_DECODED@bookstore_high@/tmp/run.sql\";
```

Also since the DB name will change, the wallet secret and passphrase secret will also be created with names `bookstore-wallet` and `bookstore-passphrase` respectively and therefore any references to those should be replaced in model.

```
weblogicDomains:
  [...]
  - name: bobs-bookstore
    [...]
    domainCRValues:
      [...]
      serverPod:
        [..]
        volumes:
            - name: creds-raw
              secret:
                secretName: bookstore-wallet
            - name: creds
              emptyDir: {}
        [...]
        volumeMounts:
            - name: creds
              mountPath: /db/wallet
        initContainers:
            - name: decode-creds
            [...]
            - name: create-schema
              env:
              - name: TNS_ADMIN
                value: "/db/wallet"
              - name: DB_ADMIN_USER
                valueFrom:
                  secretKeyRef:
                    name: bookstore-wallet
                    key: user_name
              - name: DB_ADMIN_PWD
                valueFrom:
                  secretKeyRef:
                    name: bookstore-passphrase
                    key: password 
              - name: SQL
                value: |  
                [...]
              command:
              - bash
              - -c
              - "DB_ADMIN_PWD_DECODED=`echo $DB_ADMIN_PWD | base64 --decode | base64 --decode`; 
                 DB_ADMIN_USER_LOWER=${DB_ADMIN_USER,,}; 
                 echo \"$SQL\">/tmp/run.sql; 
                 COMMAND=\"sqlplus $DB_ADMIN_USER_LOWER/$DB_ADMIN_PWD_DECODED@bookstore_high@/tmp/run.sql\";
                 eval $COMMAND"                      

```