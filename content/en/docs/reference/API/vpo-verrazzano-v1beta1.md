---
title: Verrazzano v1beta1
weight: 2
---
<p>Packages:</p>
<ul>
<li>
<a href="#install.verrazzano.io%2fv1beta1">install.verrazzano.io/v1beta1</a>
</li>
</ul>
<h2 id="install.verrazzano.io/v1beta1">install.verrazzano.io/v1beta1</h2>
<p>
</p>
Resource Types:
<ul><li>
<a href="#install.verrazzano.io/v1beta1.Verrazzano">Verrazzano</a>
</li></ul>
<h3 id="install.verrazzano.io/v1beta1.Verrazzano">Verrazzano
</h3>
<p>
<p>Verrazzano specifies the Verrazzano API.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
install.verrazzano.io/v1beta1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>Verrazzano</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoSpec">
VerrazzanoSpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>components</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">
ComponentSpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Verrazzano components.</p>
</td>
</tr>
<tr>
<td>
<code>defaultVolumeSource</code></br>
<em>
<a href="https://pkg.go.dev/k8s.io/api/core/v1#VolumeSource">
Kubernetes core/v1.VolumeSource
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Defines the type of volume to be used for persistence for all components unless overridden, and can be one of
either EmptyDirVolumeSource or PersistentVolumeClaimVolumeSource. If PersistentVolumeClaimVolumeSource is
declared, then the <code>claimName</code> must reference the name of an existing <code>VolumeClaimSpecTemplate</code> declared in the
<code>volumeClaimSpecTemplates</code> section.</p>
</td>
</tr>
<tr>
<td>
<code>environmentName</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Name of the installation. This name is part of the endpoint access URLs that are generated.
The default value is <code>default</code>.</p>
</td>
</tr>
<tr>
<td>
<code>profile</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ProfileType">
ProfileType
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The installation profile to select. Valid values are <code>prod</code> (production), <code>dev</code> (development), and <code>managed-cluster</code>.
The default is <code>prod</code>.</p>
</td>
</tr>
<tr>
<td>
<code>security</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.SecuritySpec">
SecuritySpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Security specifies Verrazzano security configuration.</p>
</td>
</tr>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The version to install. Valid versions can be found
<a href="https://github.com/verrazzano/verrazzano/releases/">here</a>.
Defaults to the current version supported by the Verrazzano platform operator.</p>
</td>
</tr>
<tr>
<td>
<code>volumeClaimSpecTemplates</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.VolumeClaimSpecTemplate">
[]VolumeClaimSpecTemplate
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Defines a named set of PVC configurations that can be referenced from components to configure persistent volumes.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoStatus">
VerrazzanoStatus
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.Acme">Acme
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.Certificate">Certificate</a>)
</p>
<p>
<p>Acme identifies the ACME cert issuer.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>emailAddress</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Email address of the user.</p>
</td>
</tr>
<tr>
<td>
<code>environment</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Environment.</p>
</td>
</tr>
<tr>
<td>
<code>provider</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ProviderType">
ProviderType
</a>
</em>
</td>
<td>
<p>Name of the Acme provider.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.ApplicationOperatorComponent">ApplicationOperatorComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>ApplicationOperatorComponent specifies the Application Operator configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then the Application Operator will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/helm_config/charts/verrazzano-application-operator/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.ArgoCDComponent">ArgoCDComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>ArgoCDComponent specifies the Argo CD configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Argo CD will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/argo-cd/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.AuthProxyComponent">AuthProxyComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>AuthProxyComponent specifies the AuthProxy configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then AuthProxy will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/helm_config/charts/verrazzano-authproxy/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.CA">CA
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.Certificate">Certificate</a>)
</p>
<p>
<p>CA identifies the Certificate Authority cert issuer.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>clusterResourceNamespace</code></br>
<em>
string
</em>
</td>
<td>
<p>The secret namespace.</p>
</td>
</tr>
<tr>
<td>
<code>secretName</code></br>
<em>
string
</em>
</td>
<td>
<p>The secret name.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.CAPIComponent">CAPIComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>CAPIComponent specifies the CAPI configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then CAPI Providers will be installed.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.CertManagerComponent">CertManagerComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>CertManagerComponent specifies the cert-manager configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>certificate</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.Certificate">
Certificate
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The certificate configuration.</p>
</td>
</tr>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then cert-manager will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/cert-manager/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.Certificate">Certificate
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.CertManagerComponent">CertManagerComponent</a>)
</p>
<p>
<p>Certificate represents the type of cert issuer for an installation.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>acme</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.Acme">
Acme
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The ACME configuration. Either <code>acme</code> or <code>ca</code> must be specified.</p>
</td>
</tr>
<tr>
<td>
<code>ca</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.CA">
CA
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The ACME configuration. Either <code>acme</code> or <code>ca</code> must be specified.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.ClusterOperatorComponent">ClusterOperatorComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>ClusterOperatorComponent specifies the Cluster Operator configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then the Cluster Operator will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/helm_config/charts/verrazzano-cluster-operator/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.CoherenceOperatorComponent">CoherenceOperatorComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>CoherenceOperatorComponent specifies the Coherence Operator configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then the Coherence Operator will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/coherence-operator/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.CompStateType">CompStateType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentStatusDetails">ComponentStatusDetails</a>)
</p>
<p>
<p>CompStateType identifies the state of a component.</p>
</p>
<h3 id="install.verrazzano.io/v1beta1.ComponentAvailability">ComponentAvailability
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentStatusDetails">ComponentStatusDetails</a>)
</p>
<p>
<p>ComponentAvailability identifies the availability of a Verrazzano Component.</p>
</p>
<h3 id="install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoSpec">VerrazzanoSpec</a>)
</p>
<p>
<p>ComponentSpec contains a set of components used by Verrazzano.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>applicationOperator</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ApplicationOperatorComponent">
ApplicationOperatorComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Application Operator component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>argoCD</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ArgoCDComponent">
ArgoCDComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Argo CD component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>authProxy</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.AuthProxyComponent">
AuthProxyComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The AuthProxy component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>capi</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.CAPIComponent">
CAPIComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The CAPI component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>certManager</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.CertManagerComponent">
CertManagerComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The cert-manager component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>clusterOperator</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ClusterOperatorComponent">
ClusterOperatorComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Cluster Operator component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>coherenceOperator</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.CoherenceOperatorComponent">
CoherenceOperatorComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Coherence Operator component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>console</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ConsoleComponent">
ConsoleComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Verrazzano Console component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>dns</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.DNSComponent">
DNSComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The DNS component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>fluentd</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.FluentdComponent">
FluentdComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Fluentd component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>grafana</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.GrafanaComponent">
GrafanaComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Grafana component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>ingressNGINX</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.IngressNginxComponent">
IngressNginxComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The ingress NGINX component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>istio</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.IstioComponent">
IstioComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Istio component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>jaegerOperator</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.JaegerOperatorComponent">
JaegerOperatorComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Jaeger Operator component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>keycloak</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.KeycloakComponent">
KeycloakComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Keycloak component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>kiali</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.KialiComponent">
KialiComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Kiali component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>kubeStateMetrics</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.KubeStateMetricsComponent">
KubeStateMetricsComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The kube-state-metrics  component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>mySQLOperator</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.MySQLOperatorComponent">
MySQLOperatorComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The MySQL Operator component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>oam</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.OAMComponent">
OAMComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The OAM component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>opensearch</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.OpenSearchComponent">
OpenSearchComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The OpenSearch component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>opensearchDashboards</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.OpenSearchDashboardsComponent">
OpenSearchDashboardsComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The OpenSearch Dashboards component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>prometheus</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.PrometheusComponent">
PrometheusComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Prometheus component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusAdapter</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.PrometheusAdapterComponent">
PrometheusAdapterComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Prometheus Adapter component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusNodeExporter</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.PrometheusNodeExporterComponent">
PrometheusNodeExporterComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Prometheus Node Exporter component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusOperator</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.PrometheusOperatorComponent">
PrometheusOperatorComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Prometheus Operator component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusPushgateway</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.PrometheusPushgatewayComponent">
PrometheusPushgatewayComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Prometheus Pushgateway component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>rancher</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.RancherComponent">
RancherComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Rancher component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>rancherBackup</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.RancherBackupComponent">
RancherBackupComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The rancherBackup component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>thanos</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ThanosComponent">
ThanosComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Thanos component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>velero</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.VeleroComponent">
VeleroComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Velero component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>verrazzano</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoComponent">
VerrazzanoComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Verrazzano component configuration.</p>
</td>
</tr>
<tr>
<td>
<code>weblogicOperator</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.WebLogicOperatorComponent">
WebLogicOperatorComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The WebLogic Kubernetes Operator component configuration.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.ComponentStatusDetails">ComponentStatusDetails
</h3>
<p>
<p>ComponentStatusDetails defines the observed state of a component.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>available</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ComponentAvailability">
ComponentAvailability
</a>
</em>
</td>
<td>
<p>Whether a component is available for use.</p>
</td>
</tr>
<tr>
<td>
<code>conditions</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.Condition">
[]Condition
</a>
</em>
</td>
<td>
<p>Information about the current state of a component.</p>
</td>
</tr>
<tr>
<td>
<code>lastReconciledGeneration</code></br>
<em>
int64
</em>
</td>
<td>
<p>The generation of the last Verrazzano resource the Component was successfully reconciled against.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name of the component.</p>
</td>
</tr>
<tr>
<td>
<code>reconcilingGeneration</code></br>
<em>
int64
</em>
</td>
<td>
<p>The generation of the Verrazzano resource the Component is currently being reconciled against.</p>
</td>
</tr>
<tr>
<td>
<code>state</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.CompStateType">
CompStateType
</a>
</em>
</td>
<td>
<p>The state of a component.</p>
</td>
</tr>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
<p>The version of a component.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.ComponentStatusMap">ComponentStatusMap
(<code>map[string]*github.com/verrazzano/verrazzano/platform-operator/apis/verrazzano/v1beta1.ComponentStatusDetails</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoStatus">VerrazzanoStatus</a>)
</p>
<p>
<p>ComponentStatusMap is a map of components status details.</p>
</p>
<h3 id="install.verrazzano.io/v1beta1.ComponentValidator">ComponentValidator
</h3>
<p>
</p>
<h3 id="install.verrazzano.io/v1beta1.Condition">Condition
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentStatusDetails">ComponentStatusDetails</a>, 
<a href="#install.verrazzano.io/v1beta1.VerrazzanoStatus">VerrazzanoStatus</a>)
</p>
<p>
<p>Condition describes the current state of an installation.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>lastTransitionTime</code></br>
<em>
string
</em>
</td>
<td>
<p>Last time the condition transitioned from one status to another.</p>
</td>
</tr>
<tr>
<td>
<code>message</code></br>
<em>
string
</em>
</td>
<td>
<p>Human readable message indicating details about the last transition.</p>
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="https://pkg.go.dev/k8s.io/api/core/v1#ConditionStatus">
Kubernetes core/v1.ConditionStatus
</a>
</em>
</td>
<td>
<p>Status of the condition: one of <code>True</code>, <code>False</code>, or <code>Unknown</code>.</p>
</td>
</tr>
<tr>
<td>
<code>type</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ConditionType">
ConditionType
</a>
</em>
</td>
<td>
<p>Type of condition.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.ConditionType">ConditionType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.Condition">Condition</a>)
</p>
<p>
<p>ConditionType identifies the condition of the install, uninstall, or upgrade, which can be checked with <code>kubectl wait</code>.</p>
</p>
<h3 id="install.verrazzano.io/v1beta1.ConsoleComponent">ConsoleComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>ConsoleComponent specifies the Verrazzano Console configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Verrazzano Console will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/helm_config/charts/verrazzano-console/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.DNSComponent">DNSComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>DNSComponent specifies the DNS configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>external</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.External">
External
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>External DNS configuration.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/external-dns/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
<tr>
<td>
<code>oci</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.OCI">
OCI
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Oracle Cloud Infrastructure DNS configuration.</p>
</td>
</tr>
<tr>
<td>
<code>wildcard</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.Wildcard">
Wildcard
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Wildcard DNS configuration. This is the default with a domain of nip.io.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.DatabaseInfo">DatabaseInfo
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.GrafanaComponent">GrafanaComponent</a>)
</p>
<p>
<p>DatabaseInfo specifies the database connection information for the Grafana DB instance.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>host</code></br>
<em>
string
</em>
</td>
<td>
<p>The host of the database.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>The name of the database.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.External">External
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.DNSComponent">DNSComponent</a>)
</p>
<p>
<p>External DNS type.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>suffix</code></br>
<em>
string
</em>
</td>
<td>
<p>The suffix for DNS names.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.FluentdComponent">FluentdComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>FluentdComponent specifies the Fluentd configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Fluentd will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>extraVolumeMounts</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.VolumeMount">
[]VolumeMount
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>A list of host path volume mounts, in addition to <code>/var/log</code>, into the Fluentd DaemonSet. The Fluentd component
collects log files in the <code>/var/log/containers</code> directory of Kubernetes worker nodes. The <code>/var/log/containers</code>
directory may contain symbolic links to files located outside the <code>/var/log</code> directory. If the host path
directory containing the log files is located outside <code>/var/log</code>, the Fluentd DaemonSet must have the volume
mount of that directory to collect the logs.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/helm_config/charts/verrazzano-fluentd/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
<tr>
<td>
<code>oci</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.OciLoggingConfiguration">
OciLoggingConfiguration
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Oracle Cloud Infrastructure Logging configuration.</p>
</td>
</tr>
<tr>
<td>
<code>opensearchSecret</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The secret containing the credentials for connecting to OpenSearch. This secret needs to be created in the
<code>verrazzano-install</code> namespace prior to creating the Verrazzano custom resource. Specify the OpenSearch login
credentials in the <code>username</code> and <code>password</code> fields in this secret. Specify the CA for verifying the OpenSearch
certificate in the <code>ca-bundle</code> field, if applicable. The default <code>verrazzano</code> is the secret for connecting to
the VMI OpenSearch.</p>
</td>
</tr>
<tr>
<td>
<code>opensearchURL</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The target OpenSearch URLs.
Specify this option in this <a href="https://docs.fluentd.org/output/opensearch#hosts-optional">format</a>.
The default <code>http://vmi-system-es-ingest-oidc:8775</code> is the VMI OpenSearch URL.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.GrafanaComponent">GrafanaComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>GrafanaComponent specifies the Grafana configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>database</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.DatabaseInfo">
DatabaseInfo
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The information to configure a connection to an external Grafana database.</p>
</td>
</tr>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Grafana will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>replicas</code></br>
<em>
int32
</em>
</td>
<td>
<em>(Optional)</em>
<p>The number of pods to replicate. The default is <code>1</code>.</p>
</td>
</tr>
<tr>
<td>
<code>smtp</code></br>
<em>
<a href="https://pkg.go.dev/github.com/verrazzano/verrazzano-monitoring-operator/pkg/apis/vmcontroller/v1#SMTPInfo">
VMO /vmcontroller/v1.SMTPInfo
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The SMTP notification settings.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.IngressNginxComponent">IngressNginxComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>IngressNginxComponent specifies the ingress NGINX configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then ingress NGINX will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>ingressClassName</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Name of the ingress class used by the ingress controller. Defaults to <code>verrazzano-nginx</code>.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/ingress-nginx/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
<tr>
<td>
<code>ports</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#serviceport-v1-core">
[]Kubernetes core/v1.ServicePort
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The list of port configurations used by the ingress.</p>
</td>
</tr>
<tr>
<td>
<code>type</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.IngressType">
IngressType
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The ingress type. Valid values are <code>LoadBalancer</code> and <code>NodePort</code>. The default value is <code>LoadBalancer</code>. If the ingress
type is <code>NodePort</code>, then a valid and accessible IP address must be specified using the <code>controller.service.externalIPs</code>
key in the <a href="#install.verrazzano.io/v1beta1.InstallOverrides">InstallOverrides</a>. For sample usage, see
<a href="../../../../docs/customize/externallbs/">External Load Balancers</a>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.IngressType">IngressType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.IngressNginxComponent">IngressNginxComponent</a>)
</p>
<p>
<p>IngressType is the type of ingress.</p>
</p>
<h3 id="install.verrazzano.io/v1beta1.InstallOverrides">InstallOverrides
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ApplicationOperatorComponent">ApplicationOperatorComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.ArgoCDComponent">ArgoCDComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.AuthProxyComponent">AuthProxyComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.CertManagerComponent">CertManagerComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.ClusterOperatorComponent">ClusterOperatorComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.CoherenceOperatorComponent">CoherenceOperatorComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.ConsoleComponent">ConsoleComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.DNSComponent">DNSComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.FluentdComponent">FluentdComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.IngressNginxComponent">IngressNginxComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.IstioComponent">IstioComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.JaegerOperatorComponent">JaegerOperatorComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.KeycloakComponent">KeycloakComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.KialiComponent">KialiComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.KubeStateMetricsComponent">KubeStateMetricsComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.MySQLComponent">MySQLComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.MySQLOperatorComponent">MySQLOperatorComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.OAMComponent">OAMComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.PrometheusAdapterComponent">PrometheusAdapterComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.PrometheusNodeExporterComponent">PrometheusNodeExporterComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.PrometheusOperatorComponent">PrometheusOperatorComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.PrometheusPushgatewayComponent">PrometheusPushgatewayComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.RancherBackupComponent">RancherBackupComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.RancherComponent">RancherComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.ThanosComponent">ThanosComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.VeleroComponent">VeleroComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.VerrazzanoComponent">VerrazzanoComponent</a>, 
<a href="#install.verrazzano.io/v1beta1.WebLogicOperatorComponent">WebLogicOperatorComponent</a>)
</p>
<p>
<p>InstallOverrides are used to pass installation overrides to components.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>monitorChanges</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If false, then Verrazzano updates will ignore any configuration changes to this component. Defaults to <code>true</code>.</p>
</td>
</tr>
<tr>
<td>
<code>overrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.Overrides">
[]Overrides
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>List of overrides for the default values.yaml file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others.
Invalid override values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.InstanceInfo">InstanceInfo
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoStatus">VerrazzanoStatus</a>)
</p>
<p>
<p>InstanceInfo details of the installed Verrazzano instance maintained in status field.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>argoCDUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The Argo CD UI URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>consoleUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The Console URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>grafanaUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The Grafana URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>jaegerUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The Jaeger UI URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>keyCloakUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The KeyCloak URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>kialiUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The Kiali URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>openSearchDashboardsUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The OpenSearch Dashboards URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>openSearchUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The OpenSearch URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The Prometheus URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>rancherUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The Rancher URL for this Verrazzano installation.</p>
</td>
</tr>
<tr>
<td>
<code>thanosQueryUrl</code></br>
<em>
string
</em>
</td>
<td>
<p>The Thanos Query URL for this Verrazzano installation.
The Thanos Query ingress gets forwarded to the Thanos Query Frontend service.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.IstioComponent">IstioComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>IstioComponent specifies the Istio configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Istio will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>injectionEnabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Istio sidecar injection enabled for installed components.  Default is <code>true</code>.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for default IstioOperator. Overrides are merged together, but in the event of conflicting
fields, the last override in the list takes precedence over any others. You can find all possible values
<a href="https://istio.io/v1.13/docs/reference/config/istio.operator.v1alpha1/#IstioOperatorSpec">here</a>
Passing through an invalid IstioOperator resource will result in an error.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.JaegerOperatorComponent">JaegerOperatorComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>JaegerOperatorComponent specifies the Jaeger Operator configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Jaeger Operator will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/jaegertracing/jaeger-operator/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.KeycloakComponent">KeycloakComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>KeycloakComponent specifies the Keycloak configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Keycloak will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/keycloak/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
<tr>
<td>
<code>mysql</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.MySQLComponent">
MySQLComponent
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Contains the MySQL component configuration needed for Keycloak.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.KialiComponent">KialiComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>KialiComponent specifies the Kiali configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Kiali will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/kiali-server/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.KubeStateMetricsComponent">KubeStateMetricsComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>KubeStateMetricsComponent specifies the kube-state-metrics configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then kube-state-metrics will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/prometheus-community/kube-state-metrics/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.MySQLComponent">MySQLComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.KeycloakComponent">KeycloakComponent</a>)
</p>
<p>
<p>MySQLComponent specifies the MySQL configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/mysql/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
<tr>
<td>
<code>volumeSource</code></br>
<em>
<a href="https://pkg.go.dev/k8s.io/api/core/v1#VolumeSource">
Kubernetes core/v1.VolumeSource
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Defines the type of volume to be used for persistence for Keycloak/MySQL, and can be one of either
EmptyDirVolumeSource or PersistentVolumeClaimVolumeSource. If PersistentVolumeClaimVolumeSource is declared,
then the <code>claimName</code> must reference the name of a <code>VolumeClaimSpecTemplate</code> declared in the
<code>volumeClaimSpecTemplates</code> section.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.MySQLOperatorComponent">MySQLOperatorComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>MySQLOperatorComponent specifies the MySQL Operator configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then MySQL Operator will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/mysql-operator/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.OAMComponent">OAMComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>OAMComponent specifies the OAM configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then OAM will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/oam-kubernetes-runtime/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.OCI">OCI
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.DNSComponent">DNSComponent</a>)
</p>
<p>
<p>OCI DNS type.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>dnsScope</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Scope of the Oracle Cloud Infrastructure DNS zone (<code>PRIVATE</code>, <code>GLOBAL</code>). If not specified, then defaults to <code>GLOBAL</code>.</p>
</td>
</tr>
<tr>
<td>
<code>dnsZoneCompartmentOCID</code></br>
<em>
string
</em>
</td>
<td>
<p>The Oracle Cloud Infrastructure DNS compartment OCID.</p>
</td>
</tr>
<tr>
<td>
<code>dnsZoneOCID</code></br>
<em>
string
</em>
</td>
<td>
<p>The Oracle Cloud Infrastructure DNS zone OCID.</p>
</td>
</tr>
<tr>
<td>
<code>dnsZoneName</code></br>
<em>
string
</em>
</td>
<td>
<p>Name of Oracle Cloud Infrastructure DNS zone.</p>
</td>
</tr>
<tr>
<td>
<code>ociConfigSecret</code></br>
<em>
string
</em>
</td>
<td>
<p>Name of the Oracle Cloud Infrastructure configuration secret. Generate a secret based on the
Oracle Cloud Infrastructure configuration profile you want to use. You can specify a profile other than
<code>DEFAULT</code> and specify the secret name. See instructions by running <code>./install/create_oci_config_secret.sh</code>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.OciLoggingConfiguration">OciLoggingConfiguration
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.FluentdComponent">FluentdComponent</a>)
</p>
<p>
<p>OciLoggingConfiguration is the Oracle Cloud Infrastructure logging configuration for Fluentd.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiSecret</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the secret containing the Oracle Cloud Infrastructure API configuration and private key.</p>
</td>
</tr>
<tr>
<td>
<code>defaultAppLogId</code></br>
<em>
string
</em>
</td>
<td>
<p>The OCID of the Oracle Cloud Infrastructure Log that will collect application logs.</p>
</td>
</tr>
<tr>
<td>
<code>systemLogId</code></br>
<em>
string
</em>
</td>
<td>
<p>The OCID of the Oracle Cloud Infrastructure Log that will collect system logs.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.OpenSearchComponent">OpenSearchComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>OpenSearchComponent specifies the OpenSearch configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then OpenSearch will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>nodes</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.OpenSearchNode">
[]OpenSearchNode
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>A list of OpenSearch node groups. For sample usage, see
<a href="../../../../docs/customize/opensearch/">Customize OpenSearch</a>.</p>
</td>
</tr>
<tr>
<td>
<code>policies</code></br>
<em>
<a href="https://pkg.go.dev/github.com/verrazzano/verrazzano-monitoring-operator/pkg/apis/vmcontroller/v1#IndexManagementPolicy">
[]VMO /vmcontroller/v1.IndexManagementPolicy
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>A list of <a href="https://opensearch.org/docs/2.3/im-plugin/ism/index/">Index State Management</a> policies
to enable on OpenSearch.</p>
</td>
</tr>
<tr>
<td>
<code>plugins</code></br>
<em>
<a href="https://pkg.go.dev/github.com/verrazzano/verrazzano-monitoring-operator/pkg/apis/vmcontroller/v1#OpenSearchPlugins">
VMO /vmcontroller/v1.OpenSearchPlugins
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Enable to add 3rd Party / Custom plugins not offered in the default OpenSearch image.</p>
</td>
</tr>
<tr>
<td>
<code>disableDefaultPolicy</code></br>
<em>
bool
</em>
</td>
<td>
<p>To disable the default ISM policies.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.OpenSearchDashboardsComponent">OpenSearchDashboardsComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>OpenSearchDashboardsComponent specifies the OpenSearch Dashboards configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then OpenSearch Dashboards will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>replicas</code></br>
<em>
int32
</em>
</td>
<td>
<p>The number of pods to replicate. The default is <code>1</code>.</p>
</td>
</tr>
<tr>
<td>
<code>plugins</code></br>
<em>
<a href="https://pkg.go.dev/github.com/verrazzano/verrazzano-monitoring-operator/pkg/apis/vmcontroller/v1#OpenSearchDashboardsPlugins">
VMO /vmcontroller/v1.OpenSearchDashboardsPlugins
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Enable to add 3rd Party / Custom plugins not offered in the default OpenSearch-Dashboard image</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.OpenSearchNode">OpenSearchNode
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.OpenSearchComponent">OpenSearchComponent</a>)
</p>
<p>
<p>OpenSearchNode specifies a node group in the OpenSearch cluster.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name of the node group.</p>
</td>
</tr>
<tr>
<td>
<code>replicas</code></br>
<em>
int32
</em>
</td>
<td>
<em>(Optional)</em>
<p>Node group replica count.</p>
</td>
</tr>
<tr>
<td>
<code>resources</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#resourcerequirements-v1-core">
Kubernetes core/v1.ResourceRequirements
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Kubernetes container resources for nodes in the node group.</p>
</td>
</tr>
<tr>
<td>
<code>roles</code></br>
<em>
<a href="https://pkg.go.dev/github.com/verrazzano/verrazzano-monitoring-operator/pkg/apis/vmcontroller/v1#NodeRole">
[]VMO /vmcontroller/v1.NodeRole
</a>
</em>
</td>
<td>
<p>Role or roles that nodes in the group will assume: may be <code>master</code>, <code>data</code>, and/or <code>ingest</code>.</p>
</td>
</tr>
<tr>
<td>
<code>storage</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.OpenSearchNodeStorage">
OpenSearchNodeStorage
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Storage settings for the node group.</p>
</td>
</tr>
<tr>
<td>
<code>javaOpts</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>JavaOpts settings for the OpenSearch JVM.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.OpenSearchNodeStorage">OpenSearchNodeStorage
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.OpenSearchNode">OpenSearchNode</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>size</code></br>
<em>
string
</em>
</td>
<td>
<p>Node group storage size expressed as a
<a href="https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/#Quantity">Quantity</a>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.Overrides">Overrides
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">InstallOverrides</a>)
</p>
<p>
<p>Overrides identifies overrides for a component.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>configMapRef</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#configmapkeyselector-v1-core">
Kubernetes core/v1.ConfigMapKeySelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Selector for ConfigMap containing override data.
For sample usage, see
<a href="../../../../docs/customize/installationoverrides/#configmap">ConfigMapRef</a>.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#secretkeyselector-v1-core">
Kubernetes core/v1.SecretKeySelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Selector for Secret containing override data.
For sample usage, see
<a href="../../../../docs/customize/installationoverrides/#secret">SecretRef</a>.</p>
</td>
</tr>
<tr>
<td>
<code>values</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#json-v1-apiextensions-k8s-io">
Kubernetes apiextensions/v1.JSON
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Configure overrides using inline YAML.
For sample usage, see
<a href="../../../../docs/customize/installationoverrides/#values">Values</a>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.ProfileType">ProfileType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoSpec">VerrazzanoSpec</a>)
</p>
<p>
<p>ProfileType is the type of installation profile.</p>
</p>
<h3 id="install.verrazzano.io/v1beta1.PrometheusAdapterComponent">PrometheusAdapterComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>PrometheusAdapterComponent specifies the Prometheus Adapter configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Prometheus Adaptor will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/prometheus-community/prometheus-adapter/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.PrometheusComponent">PrometheusComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>PrometheusComponent specifies the Prometheus configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Prometheus will be installed.
This is a legacy setting; the preferred way to configure Prometheus is using the
<a href="#install.verrazzano.io/v1beta1.PrometheusOperatorComponent">PrometheusOperatorComponent</a>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.PrometheusNodeExporterComponent">PrometheusNodeExporterComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>PrometheusNodeExporterComponent specifies the Prometheus Node Exporter configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Prometheus Node Exporter will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/prometheus-community/prometheus-node-exporter/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.PrometheusOperatorComponent">PrometheusOperatorComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>PrometheusOperatorComponent specifies the Prometheus Operator configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Prometheus Operator will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/prometheus-community/kube-prometheus-stack/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.PrometheusPushgatewayComponent">PrometheusPushgatewayComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>PrometheusPushgatewayComponent specifies the Prometheus Pushgateway configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Prometheus Pushgateway will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/prometheus-community/prometheus-pushgateway/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.ProviderType">ProviderType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.Acme">Acme</a>)
</p>
<p>
<p>ProviderType identifies Acme provider type.</p>
</p>
<h3 id="install.verrazzano.io/v1beta1.RancherBackupComponent">RancherBackupComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>RancherBackupComponent specifies the rancherBackup configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then rancherBackup will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/rancher-backup/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.RancherComponent">RancherComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>RancherComponent specifies the Rancher configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Rancher will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/rancher/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
<tr>
<td>
<code>keycloakAuthEnabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>KeycloakAuthEnabled specifies whether the Keycloak Auth provider is enabled.  Default is <code>false</code>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.SecuritySpec">SecuritySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoSpec">VerrazzanoSpec</a>)
</p>
<p>
<p>SecuritySpec defines the security configuration for Verrazzano.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>adminSubjects</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#subject-v1-rbac-authorization-k8s-io">
[]Kubernetes rbac/v1.Subject
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Specifies subjects that should be bound to the verrazzano-admin role.</p>
</td>
</tr>
<tr>
<td>
<code>monitorSubjects</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#subject-v1-rbac-authorization-k8s-io">
[]Kubernetes rbac/v1.Subject
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Specifies subjects that should be bound to the verrazzano-monitor role.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.ThanosComponent">ThanosComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>ThanosComponent specifies the Thanos configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Thanos will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/thanos/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.VeleroComponent">VeleroComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>VeleroComponent specifies the Velero configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Velero will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/velero/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.VerrazzanoComponent">VerrazzanoComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>VerrazzanoComponent specifies the Verrazzano configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then Verrazzano will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/helm_config/charts/verrazzano/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.VerrazzanoSpec">VerrazzanoSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.Verrazzano">Verrazzano</a>)
</p>
<p>
<p>VerrazzanoSpec defines the desired state of Verrazzano resource.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>components</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">
ComponentSpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Verrazzano components.</p>
</td>
</tr>
<tr>
<td>
<code>defaultVolumeSource</code></br>
<em>
<a href="https://pkg.go.dev/k8s.io/api/core/v1#VolumeSource">
Kubernetes core/v1.VolumeSource
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Defines the type of volume to be used for persistence for all components unless overridden, and can be one of
either EmptyDirVolumeSource or PersistentVolumeClaimVolumeSource. If PersistentVolumeClaimVolumeSource is
declared, then the <code>claimName</code> must reference the name of an existing <code>VolumeClaimSpecTemplate</code> declared in the
<code>volumeClaimSpecTemplates</code> section.</p>
</td>
</tr>
<tr>
<td>
<code>environmentName</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Name of the installation. This name is part of the endpoint access URLs that are generated.
The default value is <code>default</code>.</p>
</td>
</tr>
<tr>
<td>
<code>profile</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ProfileType">
ProfileType
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The installation profile to select. Valid values are <code>prod</code> (production), <code>dev</code> (development), and <code>managed-cluster</code>.
The default is <code>prod</code>.</p>
</td>
</tr>
<tr>
<td>
<code>security</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.SecuritySpec">
SecuritySpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Security specifies Verrazzano security configuration.</p>
</td>
</tr>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The version to install. Valid versions can be found
<a href="https://github.com/verrazzano/verrazzano/releases/">here</a>.
Defaults to the current version supported by the Verrazzano platform operator.</p>
</td>
</tr>
<tr>
<td>
<code>volumeClaimSpecTemplates</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.VolumeClaimSpecTemplate">
[]VolumeClaimSpecTemplate
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Defines a named set of PVC configurations that can be referenced from components to configure persistent volumes.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.VerrazzanoStatus">VerrazzanoStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.Verrazzano">Verrazzano</a>)
</p>
<p>
<p>VerrazzanoStatus defines the observed state of a Verrazzano resource.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>available</code></br>
<em>
string
</em>
</td>
<td>
<p>The summary of Verrazzano component availability.</p>
</td>
</tr>
<tr>
<td>
<code>components</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.ComponentStatusMap">
ComponentStatusMap
</a>
</em>
</td>
<td>
<p>States of the individual installed components.</p>
</td>
</tr>
<tr>
<td>
<code>conditions</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.Condition">
[]Condition
</a>
</em>
</td>
<td>
<p>The latest available observations of an object&rsquo;s current state.</p>
</td>
</tr>
<tr>
<td>
<code>state</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.VzStateType">
VzStateType
</a>
</em>
</td>
<td>
<p>State of the Verrazzano custom resource.</p>
</td>
</tr>
<tr>
<td>
<code>instance</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstanceInfo">
InstanceInfo
</a>
</em>
</td>
<td>
<p>The Verrazzano instance info.</p>
</td>
</tr>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
<p>The version of Verrazzano that is installed.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.VolumeClaimSpecTemplate">VolumeClaimSpecTemplate
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoSpec">VerrazzanoSpec</a>)
</p>
<p>
<p>VolumeClaimSpecTemplate Contains common PVC configuration that can be referenced from Components; these
do not actually result in generated PVCs, but can be used to provide common configuration to components that
declare a PersistentVolumeClaimVolumeSource.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<p>Metadata about the PersistentVolumeClaimSpec template.</p>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#persistentvolumeclaimspec-v1-core">
Kubernetes core/v1.PersistentVolumeClaimSpec
</a>
</em>
</td>
<td>
<p>A <code>PersistentVolumeClaimSpec</code> template that can be referenced by a Component to override its default storage
settings for a profile. At present, only a subset of the <code>resources.requests</code> object are honored depending on
the component.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>accessModes</code></br>
<em>
<a href="https://pkg.go.dev/k8s.io/api/core/v1#PersistentVolumeAccessMode">
[]Kubernetes core/v1.PersistentVolumeAccessMode
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>accessModes contains the desired access modes the volume should have.
More info: <a href="https://kubernetes.io/docs/concepts/storage/persistent-volumes#access-modes-1">https://kubernetes.io/docs/concepts/storage/persistent-volumes#access-modes-1</a></p>
</td>
</tr>
<tr>
<td>
<code>selector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>selector is a label query over volumes to consider for binding.</p>
</td>
</tr>
<tr>
<td>
<code>resources</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#resourcerequirements-v1-core">
Kubernetes core/v1.ResourceRequirements
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>resources represents the minimum resources the volume should have.
If RecoverVolumeExpansionFailure feature is enabled users are allowed to specify resource requirements
that are lower than previous value but must still be higher than capacity recorded in the
status field of the claim.
More info: <a href="https://kubernetes.io/docs/concepts/storage/persistent-volumes#resources">https://kubernetes.io/docs/concepts/storage/persistent-volumes#resources</a></p>
</td>
</tr>
<tr>
<td>
<code>volumeName</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>volumeName is the binding reference to the PersistentVolume backing this claim.</p>
</td>
</tr>
<tr>
<td>
<code>storageClassName</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>storageClassName is the name of the StorageClass required by the claim.
More info: <a href="https://kubernetes.io/docs/concepts/storage/persistent-volumes#class-1">https://kubernetes.io/docs/concepts/storage/persistent-volumes#class-1</a></p>
</td>
</tr>
<tr>
<td>
<code>volumeMode</code></br>
<em>
<a href="https://pkg.go.dev/k8s.io/api/core/v1#PersistentVolumeMode">
Kubernetes core/v1.PersistentVolumeMode
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>volumeMode defines what type of volume is required by the claim.
Value of Filesystem is implied when not included in claim spec.</p>
</td>
</tr>
<tr>
<td>
<code>dataSource</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#typedlocalobjectreference-v1-core">
Kubernetes core/v1.TypedLocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>dataSource field can be used to specify either:
* An existing VolumeSnapshot object (snapshot.storage.k8s.io/VolumeSnapshot)
* An existing PVC (PersistentVolumeClaim)
If the provisioner or an external controller can support the specified data source,
it will create a new volume based on the contents of the specified data source.
If the AnyVolumeDataSource feature gate is enabled, this field will always have
the same contents as the DataSourceRef field.</p>
</td>
</tr>
<tr>
<td>
<code>dataSourceRef</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#typedlocalobjectreference-v1-core">
Kubernetes core/v1.TypedLocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>dataSourceRef specifies the object from which to populate the volume with data, if a non-empty
volume is desired. This may be any local object from a non-empty API group (non
core object) or a PersistentVolumeClaim object.
When this field is specified, volume binding will only succeed if the type of
the specified object matches some installed volume populator or dynamic
provisioner.
This field will replace the functionality of the DataSource field and as such
if both fields are non-empty, they must have the same value. For backwards
compatibility, both fields (DataSource and DataSourceRef) will be set to the same
value automatically if one of them is empty and the other is non-empty.
There are two important differences between DataSource and DataSourceRef:
* While DataSource only allows two specific types of objects, DataSourceRef
allows any non-core object, as well as PersistentVolumeClaim objects.
* While DataSource ignores disallowed values (dropping them), DataSourceRef
preserves all values, and generates an error if a disallowed value is
specified.
(Beta) Using this field requires the AnyVolumeDataSource feature gate to be enabled.</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.VolumeMount">VolumeMount
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.FluentdComponent">FluentdComponent</a>)
</p>
<p>
<p>VolumeMount defines a hostPath type Volume mount.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>destination</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The destination path on the Fluentd Container, defaults to the source host path.</p>
</td>
</tr>
<tr>
<td>
<code>readOnly</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Specifies if the volume mount is read-only, defaults to <code>true</code>.</p>
</td>
</tr>
<tr>
<td>
<code>source</code></br>
<em>
string
</em>
</td>
<td>
<p>The source host path.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.VzStateType">VzStateType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.VerrazzanoStatus">VerrazzanoStatus</a>)
</p>
<p>
<p>VzStateType identifies the state of a Verrazzano installation.</p>
</p>
<h3 id="install.verrazzano.io/v1beta1.WebLogicOperatorComponent">WebLogicOperatorComponent
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.ComponentSpec">ComponentSpec</a>)
</p>
<p>
<p>WebLogicOperatorComponent specifies the WebLogic Kubernetes Operator configuration.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>If true, then the WebLogic Kubernetes Operator will be installed.</p>
</td>
</tr>
<tr>
<td>
<code>InstallOverrides</code></br>
<em>
<a href="#install.verrazzano.io/v1beta1.InstallOverrides">
InstallOverrides
</a>
</em>
</td>
<td>
<p>
(Members of <code>InstallOverrides</code> are embedded into this type.)
</p>
<em>(Optional)</em>
<p>List of Overrides for the default <code>values.yaml</code> file for the component Helm chart. Overrides are merged together,
but in the event of conflicting fields, the last override in the list takes precedence over any others. You can
find all possible values
<a href="{{% release_source_url path=platform-operator/thirdparty/charts/weblogic-operator/values.yaml %}}">here</a>
and invalid values will be ignored.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="install.verrazzano.io/v1beta1.Wildcard">Wildcard
</h3>
<p>
(<em>Appears on:</em>
<a href="#install.verrazzano.io/v1beta1.DNSComponent">DNSComponent</a>)
</p>
<p>
<p>Wildcard DNS type.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>domain</code></br>
<em>
string
</em>
</td>
<td>
<p>The type of wildcard DNS domain. For example, nip.io, sslip.io, and such.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <code>gen-crd-api-reference-docs</code>
</em></p>
