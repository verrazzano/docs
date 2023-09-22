---
title: Traits and Workloads
weight: 2
aliases:
  - /docs/reference/api/vao-oam-v1alpha1
---
<p>Packages:</p>
<ul>
<li>
<a href="#oam.verrazzano.io%2fv1alpha1">oam.verrazzano.io/v1alpha1</a>
</li>
</ul>
<h2 id="oam.verrazzano.io/v1alpha1">oam.verrazzano.io/v1alpha1</h2>
<div>
</div>
Resource Types:
<ul><li>
<a href="#oam.verrazzano.io/v1alpha1.IngressTrait">IngressTrait</a>
</li><li>
<a href="#oam.verrazzano.io/v1alpha1.LoggingTrait">LoggingTrait</a>
</li><li>
<a href="#oam.verrazzano.io/v1alpha1.MetricsTrait">MetricsTrait</a>
</li><li>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoCoherenceWorkload">VerrazzanoCoherenceWorkload</a>
</li><li>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkload">VerrazzanoHelidonWorkload</a>
</li><li>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkload">VerrazzanoWebLogicWorkload</a>
</li></ul>
<h3 id="oam.verrazzano.io/v1alpha1.IngressTrait">IngressTrait
</h3>
<div>
<p>IngressTrait specifies the ingress traits API.</p>
</div>
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
<code>apiVersion</code><br/>
string</td>
<td>
<code>
oam.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>IngressTrait</code></td>
</tr>
<tr>
<td>
<code>metadata</code><br/>
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
<code>spec</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.IngressTraitSpec">
IngressTraitSpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>rules</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.IngressRule">
[]IngressRule
</a>
</em>
</td>
<td>
<p>A list of ingress rules for an ingress trait.</p>
</td>
</tr>
<tr>
<td>
<code>tls</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.IngressSecurity">
IngressSecurity
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The security parameters for an ingress trait.
This is required only if specific hosts are given in an <a href="#oam.verrazzano.io/v1alpha1.IngressRule">IngressRule</a>.</p>
</td>
</tr>
<tr>
<td>
<code>workloadRef</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#TypedReference">
OAM common/v1.TypedReference
</a>
</em>
</td>
<td>
<p>The WorkloadReference of the workload to which this trait applies.
This value is populated by the OAM runtime when an ApplicationConfiguration
resource is processed.  When the ApplicationConfiguration is processed, a trait and
a workload resource are created from the content of the ApplicationConfiguration.
The WorkloadReference is provided in the trait by OAM to ensure that the trait controller
can find the workload associated with the component containing the trait within the
original ApplicationConfiguration.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.IngressTraitStatus">
IngressTraitStatus
</a>
</em>
</td>
<td>
<p>The observed state of an ingress trait and related resources.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.LoggingTrait">LoggingTrait
</h3>
<div>
<p>LoggingTrait specifies the logging traits API.</p>
</div>
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
<code>apiVersion</code><br/>
string</td>
<td>
<code>
oam.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>LoggingTrait</code></td>
</tr>
<tr>
<td>
<code>metadata</code><br/>
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
<code>spec</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.LoggingTraitSpec">
LoggingTraitSpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>imagePullPolicy</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The optional image pull policy for the Fluentd image provided by the user.</p>
</td>
</tr>
<tr>
<td>
<code>loggingConfig</code><br/>
<em>
string
</em>
</td>
<td>
<p>The configuration provided by the user for the Fluentd configuration that consists of
fluentd.conf: <code>&lt;source&gt;\n ... and so on ...\n</code>.</p>
</td>
</tr>
<tr>
<td>
<code>loggingImage</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the custom Fluentd image.</p>
</td>
</tr>
<tr>
<td>
<code>workloadRef</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#TypedReference">
OAM common/v1.TypedReference
</a>
</em>
</td>
<td>
<p>The WorkloadReference of the workload to which this trait applies.
This value is populated by the OAM runtime when an ApplicationConfiguration
resource is processed.  When the ApplicationConfiguration is processed, a trait and
a workload resource are created from the content of the ApplicationConfiguration.
The WorkloadReference is provided in the trait by OAM to ensure that the trait controller
can find the workload associated with the component containing the trait within the
original ApplicationConfiguration.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.LoggingTraitStatus">
LoggingTraitStatus
</a>
</em>
</td>
<td>
<p>The observed state of a logging trait and related resources.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.MetricsTrait">MetricsTrait
</h3>
<div>
<p>MetricsTrait specifies the metrics trait API.</p>
</div>
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
<code>apiVersion</code><br/>
string</td>
<td>
<code>
oam.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>MetricsTrait</code></td>
</tr>
<tr>
<td>
<code>metadata</code><br/>
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
<code>spec</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.MetricsTraitSpec">
MetricsTraitSpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>enabled</code><br/>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Specifies whether metrics collection is enabled. Defaults to <code>true</code>.</p>
</td>
</tr>
<tr>
<td>
<code>path</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The HTTP path for the related metrics endpoint. Defaults to <code>/metrics</code>.</p>
</td>
</tr>
<tr>
<td>
<code>port</code><br/>
<em>
int
</em>
</td>
<td>
<em>(Optional)</em>
<p>The HTTP port for the related metrics trait. Defaults to <code>8080</code>.</p>
</td>
</tr>
<tr>
<td>
<code>ports</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.PortSpec">
[]PortSpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The HTTP endpoints for the related metrics.</p>
</td>
</tr>
<tr>
<td>
<code>scraper</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Prometheus deployment used to scrape the related metrics endpoints. By default, the Verrazzano-supplied
Prometheus component is used to scrape the endpoint.</p>
</td>
</tr>
<tr>
<td>
<code>secret</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of an opaque secret (for example, <code>username</code> and <code>password</code>) within the workload’s namespace for metrics
endpoint access.</p>
</td>
</tr>
<tr>
<td>
<code>workloadRef</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#TypedReference">
OAM common/v1.TypedReference
</a>
</em>
</td>
<td>
<p>The WorkloadReference of the workload to which this trait applies.
This value is populated by the OAM runtime when an ApplicationConfiguration
resource is processed.  When the ApplicationConfiguration is processed, a trait and
a workload resource are created from the content of the ApplicationConfiguration.
The WorkloadReference is provided in the trait by OAM to ensure that the trait controller
can find the workload associated with the component containing the trait within the
original ApplicationConfiguration.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.MetricsTraitStatus">
MetricsTraitStatus
</a>
</em>
</td>
<td>
<p>The observed state of a metrics trait and related resources.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoCoherenceWorkload">VerrazzanoCoherenceWorkload
</h3>
<div>
<p>VerrazzanoCoherenceWorkload specifies the Verrazzano Coherence workload API.</p>
</div>
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
<code>apiVersion</code><br/>
string</td>
<td>
<code>
oam.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>VerrazzanoCoherenceWorkload</code></td>
</tr>
<tr>
<td>
<code>metadata</code><br/>
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
<code>spec</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoCoherenceWorkloadSpec">
VerrazzanoCoherenceWorkloadSpec
</a>
</em>
</td>
<td>
<p>The desired state of a Verrazzano Coherence workload.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#RawExtension">
Kubernetes runtime.RawExtension
</a>
</em>
</td>
<td>
<p>The metadata and spec for the underlying
<a href="https://oracle.github.io/coherence-operator/docs/latest/#/docs/about/04_coherence_spec">Coherence</a> resource.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoCoherenceWorkloadStatus">
VerrazzanoCoherenceWorkloadStatus
</a>
</em>
</td>
<td>
<p>The observed state of a Verrazzano Coherence workload.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkload">VerrazzanoHelidonWorkload
</h3>
<div>
<p>VerrazzanoHelidonWorkload specifies the Verrazzano Helidon workload API.</p>
</div>
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
<code>apiVersion</code><br/>
string</td>
<td>
<code>
oam.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>VerrazzanoHelidonWorkload</code></td>
</tr>
<tr>
<td>
<code>metadata</code><br/>
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
<code>spec</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkloadSpec">
VerrazzanoHelidonWorkloadSpec
</a>
</em>
</td>
<td>
<p>The desired state of a Verrazzano Helidon workload.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>deploymentTemplate</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.DeploymentTemplate">
DeploymentTemplate
</a>
</em>
</td>
<td>
<p>An embedded Helidon application deployment.</p>
</td>
</tr>
<tr>
<td>
<code>serviceTemplate</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.ServiceTemplate">
ServiceTemplate
</a>
</em>
</td>
<td>
<p>An embedded Helidon application service.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkloadStatus">
VerrazzanoHelidonWorkloadStatus
</a>
</em>
</td>
<td>
<p>The observed state of a Verrazzano Helidon workload.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkload">VerrazzanoWebLogicWorkload
</h3>
<div>
<p>VerrazzanoWebLogicWorkload specifies the Verrazzano WebLogic workload API.</p>
</div>
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
<code>apiVersion</code><br/>
string</td>
<td>
<code>
oam.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>VerrazzanoWebLogicWorkload</code></td>
</tr>
<tr>
<td>
<code>metadata</code><br/>
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
<code>spec</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadSpec">
VerrazzanoWebLogicWorkloadSpec
</a>
</em>
</td>
<td>
<p>The desired state of a Verrazzano WebLogic workload.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadTemplate">
VerrazzanoWebLogicWorkloadTemplate
</a>
</em>
</td>
<td>
<p>The metadata and spec for the underlying
<a href="https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md">Domain</a> resource.</p>
</td>
</tr>
<tr>
<td>
<code>clusters</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadTemplate">
[]VerrazzanoWebLogicWorkloadTemplate
</a>
</em>
</td>
<td>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadStatus">
VerrazzanoWebLogicWorkloadStatus
</a>
</em>
</td>
<td>
<p>The observed state of a Verrazzano WebLogic workload.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.AuthorizationPolicy">AuthorizationPolicy
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.IngressPath">IngressPath</a>)
</p>
<div>
<p>AuthorizationPolicy defines the set of rules for authorizing a request.</p>
</div>
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
<code>rules</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.AuthorizationRule">
[]AuthorizationRule
</a>
</em>
</td>
<td>
<p>Rules are used to match requests from request principals to specific paths given an optional list of conditions.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.AuthorizationRule">AuthorizationRule
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.AuthorizationPolicy">AuthorizationPolicy</a>)
</p>
<div>
<p>AuthorizationRule matches requests from a list of request principals that access a specific path subject to a
list of conditions.</p>
</div>
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
<code>from</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.AuthorizationRuleFrom">
AuthorizationRuleFrom
</a>
</em>
</td>
<td>
<p>Specifies the request principals for access to a request. An asterisk (*) will match when the value is not empty,
for example, if any request principal is found in the request.</p>
</td>
</tr>
<tr>
<td>
<code>when</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.AuthorizationRuleCondition">
[]AuthorizationRuleCondition
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Specifies a list of additional conditions for access to a request.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.AuthorizationRuleCondition">AuthorizationRuleCondition
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.AuthorizationRule">AuthorizationRule</a>)
</p>
<div>
<p>AuthorizationRuleCondition provides additional required attributes for authorization.</p>
</div>
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
<code>key</code><br/>
<em>
string
</em>
</td>
<td>
<p>The name of a request attribute.</p>
</td>
</tr>
<tr>
<td>
<code>values</code><br/>
<em>
[]string
</em>
</td>
<td>
<p>A list of allowed values for the attribute.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.AuthorizationRuleFrom">AuthorizationRuleFrom
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.AuthorizationRule">AuthorizationRule</a>)
</p>
<div>
<p>AuthorizationRuleFrom includes a list of request principals.</p>
</div>
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
<code>requestPrincipals</code><br/>
<em>
[]string
</em>
</td>
<td>
<p>Specifies the request principals for access to a request.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.DeploymentTemplate">DeploymentTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkloadSpec">VerrazzanoHelidonWorkloadSpec</a>)
</p>
<div>
<p>DeploymentTemplate specifies the metadata and pod spec of a Helidon workload.</p>
</div>
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
<code>metadata</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<p>Metadata about a Helidon application.</p>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>podSpec</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#podspec-v1-core">
Kubernetes core/v1.PodSpec
</a>
</em>
</td>
<td>
<p>The pod spec of a Helidon application.</p>
</td>
</tr>
<tr>
<td>
<code>selector</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Label selector of a Helidon application.</p>
</td>
</tr>
<tr>
<td>
<code>strategy</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#deploymentstrategy-v1-apps">
Kubernetes apps/v1.DeploymentStrategy
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The replacement strategy of a Helidon application.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.IngressDestination">IngressDestination
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.IngressRule">IngressRule</a>)
</p>
<div>
<p>IngressDestination specifies a specific destination host and port for the ingress paths.
<div class="alert alert-warning" role="alert">
<h4 class="alert-heading">NOTE</h4>
If there are multiple ports defined for a service, then the destination port must be specified OR
the service port name must have the prefix <code>http</code>.
</div></p>
</div>
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
<code>host</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Destination host.</p>
</td>
</tr>
<tr>
<td>
<code>httpCookie</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.IngressDestinationHTTPCookie">
IngressDestinationHTTPCookie
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Session affinity cookie.</p>
</td>
</tr>
<tr>
<td>
<code>port</code><br/>
<em>
uint32
</em>
</td>
<td>
<em>(Optional)</em>
<p>Destination port.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.IngressDestinationHTTPCookie">IngressDestinationHTTPCookie
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.IngressDestination">IngressDestination</a>)
</p>
<div>
<p>IngressDestinationHTTPCookie specifies a session affinity cookie for an ingress trait.</p>
</div>
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
<code>name</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the HTTP cookie.</p>
</td>
</tr>
<tr>
<td>
<code>path</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The path of the HTTP cookie.</p>
</td>
</tr>
<tr>
<td>
<code>ttl</code><br/>
<em>
<a href="https://pkg.go.dev/time#Duration">
time.Duration
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The lifetime of the HTTP cookie (in seconds).</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.IngressPath">IngressPath
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.IngressRule">IngressRule</a>)
</p>
<div>
<p>IngressPath specifies a specific path to be exposed for an ingress trait.</p>
</div>
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
<code>path</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>If no path is provided, then it defaults to forward slash (<code>/</code>).</p>
</td>
</tr>
<tr>
<td>
<code>pathType</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Path type values are case-sensitive and formatted as follows:
<ul><li><code>exact</code>: exact string match</li><li><code>prefix</code>: prefix-based match</li><li><code>regex</code>: regex-based match</li></ul>
Defaults to <code>prefix</code> if <code>path</code> specified is <code>/</code>; otherwise, defaults to <code>exact</code>.</p>
</td>
</tr>
<tr>
<td>
<code>authorizationPolicy</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.AuthorizationPolicy">
AuthorizationPolicy
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Defines the set of rules for authorizing a request.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.IngressRule">IngressRule
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.IngressTraitSpec">IngressTraitSpec</a>)
</p>
<div>
<p>IngressRule specifies a rule for an ingress trait.</p>
</div>
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
<code>destination</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.IngressDestination">
IngressDestination
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The destination host and port for the ingress paths.</p>
</td>
</tr>
<tr>
<td>
<code>hosts</code><br/>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>One or more hosts exposed by the ingress trait. Wildcard hosts or hosts that are
empty are filtered out. If there are no valid hosts provided, then a DNS host name
is automatically generated and used.</p>
</td>
</tr>
<tr>
<td>
<code>paths</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.IngressPath">
[]IngressPath
</a>
</em>
</td>
<td>
<p>The paths to be exposed for an ingress trait.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.IngressSecurity">IngressSecurity
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.IngressTraitSpec">IngressTraitSpec</a>)
</p>
<div>
<p>IngressSecurity specifies the secret containing the certificate securing the transport for an ingress trait.</p>
</div>
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
<code>secretName</code><br/>
<em>
string
</em>
</td>
<td>
<p>The name of a secret containing the certificate securing the transport.  The specification of a secret here
implies that a certificate was created for specific hosts, as specified in an <a href="#oam.verrazzano.io/v1alpha1.IngressRule">IngressRule</a>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.IngressTraitSpec">IngressTraitSpec
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.IngressTrait">IngressTrait</a>)
</p>
<div>
<p>IngressTraitSpec specifies the desired state of an ingress trait.</p>
</div>
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
<code>rules</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.IngressRule">
[]IngressRule
</a>
</em>
</td>
<td>
<p>A list of ingress rules for an ingress trait.</p>
</td>
</tr>
<tr>
<td>
<code>tls</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.IngressSecurity">
IngressSecurity
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The security parameters for an ingress trait.
This is required only if specific hosts are given in an <a href="#oam.verrazzano.io/v1alpha1.IngressRule">IngressRule</a>.</p>
</td>
</tr>
<tr>
<td>
<code>workloadRef</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#TypedReference">
OAM common/v1.TypedReference
</a>
</em>
</td>
<td>
<p>The WorkloadReference of the workload to which this trait applies.
This value is populated by the OAM runtime when an ApplicationConfiguration
resource is processed.  When the ApplicationConfiguration is processed, a trait and
a workload resource are created from the content of the ApplicationConfiguration.
The WorkloadReference is provided in the trait by OAM to ensure that the trait controller
can find the workload associated with the component containing the trait within the
original ApplicationConfiguration.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.IngressTraitStatus">IngressTraitStatus
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.IngressTrait">IngressTrait</a>)
</p>
<div>
<p>IngressTraitStatus specifies the observed state of an ingress trait and related resources.</p>
</div>
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
<code>ConditionedStatus</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#ConditionedStatus">
OAM common/v1.ConditionedStatus
</a>
</em>
</td>
<td>
<p>
(Members of <code>ConditionedStatus</code> are embedded into this type.)
</p>
<p>Reconcile status of this ingress trait.</p>
</td>
</tr>
<tr>
<td>
<code>resources</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#TypedReference">
[]OAM common/v1.TypedReference
</a>
</em>
</td>
<td>
<p>The resources managed by this ingress trait.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.LoggingTraitSpec">LoggingTraitSpec
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.LoggingTrait">LoggingTrait</a>)
</p>
<div>
<p>LoggingTraitSpec specifies the desired state of a logging trait.</p>
</div>
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
<code>imagePullPolicy</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The optional image pull policy for the Fluentd image provided by the user.</p>
</td>
</tr>
<tr>
<td>
<code>loggingConfig</code><br/>
<em>
string
</em>
</td>
<td>
<p>The configuration provided by the user for the Fluentd configuration that consists of
fluentd.conf: <code>&lt;source&gt;\n ... and so on ...\n</code>.</p>
</td>
</tr>
<tr>
<td>
<code>loggingImage</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the custom Fluentd image.</p>
</td>
</tr>
<tr>
<td>
<code>workloadRef</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#TypedReference">
OAM common/v1.TypedReference
</a>
</em>
</td>
<td>
<p>The WorkloadReference of the workload to which this trait applies.
This value is populated by the OAM runtime when an ApplicationConfiguration
resource is processed.  When the ApplicationConfiguration is processed, a trait and
a workload resource are created from the content of the ApplicationConfiguration.
The WorkloadReference is provided in the trait by OAM to ensure that the trait controller
can find the workload associated with the component containing the trait within the
original ApplicationConfiguration.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.LoggingTraitStatus">LoggingTraitStatus
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.LoggingTrait">LoggingTrait</a>)
</p>
<div>
<p>LoggingTraitStatus specifies the observed state of a logging trait and related resources.</p>
</div>
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
<code>ConditionedStatus</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#ConditionedStatus">
OAM common/v1.ConditionedStatus
</a>
</em>
</td>
<td>
<p>
(Members of <code>ConditionedStatus</code> are embedded into this type.)
</p>
<p>Reconcile status of this logging trait.</p>
</td>
</tr>
<tr>
<td>
<code>resources</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#TypedReference">
[]OAM common/v1.TypedReference
</a>
</em>
</td>
<td>
<p>The resources managed by this logging trait.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.MetricsTraitSpec">MetricsTraitSpec
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.MetricsTrait">MetricsTrait</a>)
</p>
<div>
<p>MetricsTraitSpec specifies the desired state of a metrics trait.</p>
</div>
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
<code>enabled</code><br/>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Specifies whether metrics collection is enabled. Defaults to <code>true</code>.</p>
</td>
</tr>
<tr>
<td>
<code>path</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The HTTP path for the related metrics endpoint. Defaults to <code>/metrics</code>.</p>
</td>
</tr>
<tr>
<td>
<code>port</code><br/>
<em>
int
</em>
</td>
<td>
<em>(Optional)</em>
<p>The HTTP port for the related metrics trait. Defaults to <code>8080</code>.</p>
</td>
</tr>
<tr>
<td>
<code>ports</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.PortSpec">
[]PortSpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The HTTP endpoints for the related metrics.</p>
</td>
</tr>
<tr>
<td>
<code>scraper</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Prometheus deployment used to scrape the related metrics endpoints. By default, the Verrazzano-supplied
Prometheus component is used to scrape the endpoint.</p>
</td>
</tr>
<tr>
<td>
<code>secret</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of an opaque secret (for example, <code>username</code> and <code>password</code>) within the workload’s namespace for metrics
endpoint access.</p>
</td>
</tr>
<tr>
<td>
<code>workloadRef</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#TypedReference">
OAM common/v1.TypedReference
</a>
</em>
</td>
<td>
<p>The WorkloadReference of the workload to which this trait applies.
This value is populated by the OAM runtime when an ApplicationConfiguration
resource is processed.  When the ApplicationConfiguration is processed, a trait and
a workload resource are created from the content of the ApplicationConfiguration.
The WorkloadReference is provided in the trait by OAM to ensure that the trait controller
can find the workload associated with the component containing the trait within the
original ApplicationConfiguration.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.MetricsTraitStatus">MetricsTraitStatus
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.MetricsTrait">MetricsTrait</a>)
</p>
<div>
<p>MetricsTraitStatus defines the observed state of a metrics trait and related resources.</p>
</div>
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
<code>ConditionedStatus</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#ConditionedStatus">
OAM common/v1.ConditionedStatus
</a>
</em>
</td>
<td>
<p>
(Members of <code>ConditionedStatus</code> are embedded into this type.)
</p>
<p>Reconcile status of this metrics trait.</p>
</td>
</tr>
<tr>
<td>
<code>resources</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.QualifiedResourceRelation">
[]QualifiedResourceRelation
</a>
</em>
</td>
<td>
<p>Related resources affected by this metrics trait.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.PortSpec">PortSpec
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.MetricsTraitSpec">MetricsTraitSpec</a>)
</p>
<div>
<p>PortSpec defines an HTTP port and path combination.</p>
</div>
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
<code>path</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The HTTP path for the related metrics endpoint. Defaults to <code>/metrics</code>.</p>
</td>
</tr>
<tr>
<td>
<code>port</code><br/>
<em>
int
</em>
</td>
<td>
<em>(Optional)</em>
<p>The HTTP port for the related metrics trait. Defaults to <code>8080</code>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.QualifiedResourceRelation">QualifiedResourceRelation
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.MetricsTraitStatus">MetricsTraitStatus</a>, <a href="#oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkloadStatus">VerrazzanoHelidonWorkloadStatus</a>)
</p>
<div>
<p>QualifiedResourceRelation identifies a specific related resource.</p>
</div>
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
<code>apiversion</code><br/>
<em>
string
</em>
</td>
<td>
<p>API version of the related resource.</p>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
<em>
string
</em>
</td>
<td>
<p>Kind of the related resource.</p>
</td>
</tr>
<tr>
<td>
<code>name</code><br/>
<em>
string
</em>
</td>
<td>
<p>Name of the related resource.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code><br/>
<em>
string
</em>
</td>
<td>
<p>Namespace of the related resource.</p>
</td>
</tr>
<tr>
<td>
<code>role</code><br/>
<em>
string
</em>
</td>
<td>
<p>Role of the related resource, for example, <code>Deployment</code>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.ServiceTemplate">ServiceTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkloadSpec">VerrazzanoHelidonWorkloadSpec</a>)
</p>
<div>
<p>ServiceTemplate specifies the metadata and pod spec of a Helidon workload.</p>
</div>
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
<code>metadata</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Metadata about a Helidon application.</p>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>serviceSpec</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#servicespec-v1-core">
Kubernetes core/v1.ServiceSpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The service spec of a Helidon application.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoCoherenceWorkloadSpec">VerrazzanoCoherenceWorkloadSpec
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.VerrazzanoCoherenceWorkload">VerrazzanoCoherenceWorkload</a>)
</p>
<div>
<p>VerrazzanoCoherenceWorkloadSpec wraps a Coherence resource.</p>
</div>
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
<code>template</code><br/>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#RawExtension">
Kubernetes runtime.RawExtension
</a>
</em>
</td>
<td>
<p>The metadata and spec for the underlying
<a href="https://oracle.github.io/coherence-operator/docs/latest/#/docs/about/04_coherence_spec">Coherence</a> resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoCoherenceWorkloadStatus">VerrazzanoCoherenceWorkloadStatus
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.VerrazzanoCoherenceWorkload">VerrazzanoCoherenceWorkload</a>)
</p>
<div>
<p>VerrazzanoCoherenceWorkloadStatus defines the observed state of a Verrazzano Coherence workload.</p>
</div>
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
<code>lastGeneration</code><br/>
<em>
string
</em>
</td>
<td>
<p>The last generation of the Verrazzano Coherence workload that was reconciled.</p>
</td>
</tr>
<tr>
<td>
<code>lastRestartVersion</code><br/>
<em>
string
</em>
</td>
<td>
<p>The last value of the <code>verrazzano.io/restart-version</code> annotation.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkloadSpec">VerrazzanoHelidonWorkloadSpec
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkload">VerrazzanoHelidonWorkload</a>)
</p>
<div>
<p>VerrazzanoHelidonWorkloadSpec wraps a Helidon application deployment and service.</p>
</div>
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
<code>deploymentTemplate</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.DeploymentTemplate">
DeploymentTemplate
</a>
</em>
</td>
<td>
<p>An embedded Helidon application deployment.</p>
</td>
</tr>
<tr>
<td>
<code>serviceTemplate</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.ServiceTemplate">
ServiceTemplate
</a>
</em>
</td>
<td>
<p>An embedded Helidon application service.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkloadStatus">VerrazzanoHelidonWorkloadStatus
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.VerrazzanoHelidonWorkload">VerrazzanoHelidonWorkload</a>)
</p>
<div>
<p>VerrazzanoHelidonWorkloadStatus defines the observed state of Verrazzano Helidon workload.</p>
</div>
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
<code>ConditionedStatus</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/crossplane-runtime/apis/common/v1#ConditionedStatus">
OAM common/v1.ConditionedStatus
</a>
</em>
</td>
<td>
<p>
(Members of <code>ConditionedStatus</code> are embedded into this type.)
</p>
<p>Reconcile status of this Verrazzano Helidon workload.</p>
</td>
</tr>
<tr>
<td>
<code>resources</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.QualifiedResourceRelation">
[]QualifiedResourceRelation
</a>
</em>
</td>
<td>
<p>The resources managed by this Verrazzano Helidon workload.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadSpec">VerrazzanoWebLogicWorkloadSpec
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkload">VerrazzanoWebLogicWorkload</a>)
</p>
<div>
<p>VerrazzanoWebLogicWorkloadSpec wraps a WebLogic resource. The WebLogic domain specified
in the template must contain a spec field and it may include a metadata field.</p>
</div>
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
<code>template</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadTemplate">
VerrazzanoWebLogicWorkloadTemplate
</a>
</em>
</td>
<td>
<p>The metadata and spec for the underlying
<a href="https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md">Domain</a> resource.</p>
</td>
</tr>
<tr>
<td>
<code>clusters</code><br/>
<em>
<a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadTemplate">
[]VerrazzanoWebLogicWorkloadTemplate
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadStatus">VerrazzanoWebLogicWorkloadStatus
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkload">VerrazzanoWebLogicWorkload</a>)
</p>
<div>
<p>VerrazzanoWebLogicWorkloadStatus defines the observed state of a Verrazzano WebLogic workload.</p>
</div>
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
<code>lastGeneration</code><br/>
<em>
string
</em>
</td>
<td>
<p>The last generation of the Verrazzano WebLogic workload that was reconciled.</p>
</td>
</tr>
<tr>
<td>
<code>lastRestartVersion</code><br/>
<em>
string
</em>
</td>
<td>
<p>The last value of the <code>verrazzano.io/restart-version</code> annotation.</p>
</td>
</tr>
<tr>
<td>
<code>lastLifecycleAction</code><br/>
<em>
string
</em>
</td>
<td>
<p>The last value of the <code>verrazzano.io/lifecycle-action</code>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadTemplate">VerrazzanoWebLogicWorkloadTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkloadSpec">VerrazzanoWebLogicWorkloadSpec</a>)
</p>
<div>
</div>
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
<code>apiVersion</code><br/>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>metadata</code><br/>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#RawExtension">
Kubernetes runtime.RawExtension
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>spec</code><br/>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#RawExtension">
Kubernetes runtime.RawExtension
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>-</code><br/>
<em>
[]byte
</em>
</td>
<td>
<p>Raw is the underlying serialization of this object.</p>
<p>TODO: Determine how to detect ContentType and ContentEncoding of &lsquo;Raw&rsquo; data.</p>
</td>
</tr>
<tr>
<td>
<code>-</code><br/>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#Object">
Kubernetes runtime.Object
</a>
</em>
</td>
<td>
<p>Object can hold a representation of this extension - useful for working with versioned
structs.</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <code>gen-crd-api-reference-docs</code>
on git commit <code>3a421ac9e</code>.
</em></p>





