---
title: Metrics Binding and Metrics Template
weight: 2
---
<p>Packages:</p>
<ul>
<li>
<a href="#app.verrazzano.io%2fv1alpha1">app.verrazzano.io/v1alpha1</a>
</li>
</ul>
<h2 id="app.verrazzano.io/v1alpha1">app.verrazzano.io/v1alpha1</h2>
<p>
</p>
Resource Types:
<ul><li>
<a href="#app.verrazzano.io/v1alpha1.MetricsBinding">MetricsBinding</a>
</li><li>
<a href="#app.verrazzano.io/v1alpha1.MetricsTemplate">MetricsTemplate</a>
</li></ul>
<h3 id="app.verrazzano.io/v1alpha1.MetricsBinding">MetricsBinding
</h3>
<p>
<p>MetricsBinding specifies the metrics binding API.</p>
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
app.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>MetricsBinding</code></td>
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
<a href="#app.verrazzano.io/v1alpha1.MetricsBindingSpec">
MetricsBindingSpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>metricsTemplate</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.NamespaceName">
NamespaceName
</a>
</em>
</td>
<td>
<p>Identifies a namespace and name for a metricsTemplate resource.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusConfigMap</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.NamespaceName">
NamespaceName
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Identifies a namespace and name for a Prometheus ConfigMap resource.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusConfigSecret</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.SecretKey">
SecretKey
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Identifies a namespace, name, and key for a secret containing the Prometheus configuration.</p>
</td>
</tr>
<tr>
<td>
<code>workload</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.Workload">
Workload
</a>
</em>
</td>
<td>
<p>Identifies the name and type for a workload.</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="app.verrazzano.io/v1alpha1.MetricsTemplate">MetricsTemplate
</h3>
<p>
<p>MetricsTemplate specifies the metrics template API.</p>
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
app.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>MetricsTemplate</code></td>
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
<a href="#app.verrazzano.io/v1alpha1.MetricsTemplateSpec">
MetricsTemplateSpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>prometheusConfig</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.PrometheusConfig">
PrometheusConfig
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Prometheus configuration details.</p>
</td>
</tr>
<tr>
<td>
<code>workloadSelector</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.WorkloadSelector">
WorkloadSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Selector for target workloads.</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="app.verrazzano.io/v1alpha1.MetricsBindingSpec">MetricsBindingSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#app.verrazzano.io/v1alpha1.MetricsBinding">MetricsBinding</a>)
</p>
<p>
<p>MetricsBindingSpec specifies the desired state of a metrics binding.</p>
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
<code>metricsTemplate</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.NamespaceName">
NamespaceName
</a>
</em>
</td>
<td>
<p>Identifies a namespace and name for a metricsTemplate resource.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusConfigMap</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.NamespaceName">
NamespaceName
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Identifies a namespace and name for a Prometheus ConfigMap resource.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusConfigSecret</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.SecretKey">
SecretKey
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Identifies a namespace, name, and key for a secret containing the Prometheus configuration.</p>
</td>
</tr>
<tr>
<td>
<code>workload</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.Workload">
Workload
</a>
</em>
</td>
<td>
<p>Identifies the name and type for a workload.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="app.verrazzano.io/v1alpha1.MetricsTemplateSpec">MetricsTemplateSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#app.verrazzano.io/v1alpha1.MetricsTemplate">MetricsTemplate</a>)
</p>
<p>
<p>MetricsTemplateSpec specifies the desired state of a metrics template.</p>
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
<code>prometheusConfig</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.PrometheusConfig">
PrometheusConfig
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Prometheus configuration details.</p>
</td>
</tr>
<tr>
<td>
<code>workloadSelector</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.WorkloadSelector">
WorkloadSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Selector for target workloads.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="app.verrazzano.io/v1alpha1.NamespaceName">NamespaceName
</h3>
<p>
(<em>Appears on:</em>
<a href="#app.verrazzano.io/v1alpha1.MetricsBindingSpec">MetricsBindingSpec</a>)
</p>
<p>
<p>NamespaceName identifies a namespace and name pair for a resource.</p>
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
<p>Name of the resource.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>Namespace of the resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="app.verrazzano.io/v1alpha1.PrometheusConfig">PrometheusConfig
</h3>
<p>
(<em>Appears on:</em>
<a href="#app.verrazzano.io/v1alpha1.MetricsTemplateSpec">MetricsTemplateSpec</a>)
</p>
<p>
<p>PrometheusConfig refers to the templated metrics scraping configuration.</p>
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
<code>scrapeConfigTemplate</code></br>
<em>
string
</em>
</td>
<td>
<p>Scrape configuration template to be added to the Prometheus configuration.</p>
</td>
</tr>
<tr>
<td>
<code>targetConfigMap</code></br>
<em>
<a href="#app.verrazzano.io/v1alpha1.TargetConfigMap">
TargetConfigMap
</a>
</em>
</td>
<td>
<p>Identity of the ConfigMap to be updated with the scrape configuration specified in <code>scrapeConfigTemplate</code>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="app.verrazzano.io/v1alpha1.SecretKey">SecretKey
</h3>
<p>
(<em>Appears on:</em>
<a href="#app.verrazzano.io/v1alpha1.MetricsBindingSpec">MetricsBindingSpec</a>)
</p>
<p>
<p>SecretKey identifies a value in a Kubernetes secret by its namespace, name, and key.</p>
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
<p>Name of the secret.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>Namespace of the secret.</p>
</td>
</tr>
<tr>
<td>
<code>key</code></br>
<em>
string
</em>
</td>
<td>
<p>Key in the secret whose value this object represents.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="app.verrazzano.io/v1alpha1.TargetConfigMap">TargetConfigMap
</h3>
<p>
(<em>Appears on:</em>
<a href="#app.verrazzano.io/v1alpha1.PrometheusConfig">PrometheusConfig</a>)
</p>
<p>
<p>TargetConfigMap contains metadata about the Prometheus ConfigMap.</p>
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
<p>Name of the ConfigMap to be updated with the scrape target configuration.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>Namespace of the ConfigMap to be updated with the scrape target configuration.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="app.verrazzano.io/v1alpha1.Workload">Workload
</h3>
<p>
(<em>Appears on:</em>
<a href="#app.verrazzano.io/v1alpha1.MetricsBindingSpec">MetricsBindingSpec</a>)
</p>
<p>
<p>Workload identifies the name and type of workload.</p>
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
<p>Name of the resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="app.verrazzano.io/v1alpha1.WorkloadSelector">WorkloadSelector
</h3>
<p>
(<em>Appears on:</em>
<a href="#app.verrazzano.io/v1alpha1.MetricsTemplateSpec">MetricsTemplateSpec</a>)
</p>
<p>
<p>WorkloadSelector identifies the workloads to which a template applies.</p>
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
<code>apiGroups</code></br>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Scopes the template to given API Groups.</p>
</td>
</tr>
<tr>
<td>
<code>apiVersions</code></br>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Scopes the template to given API Versions.</p>
</td>
</tr>
<tr>
<td>
<code>namespaceSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Scopes the template to a namespace.</p>
</td>
</tr>
<tr>
<td>
<code>objectSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Scopes the template to a specifically-labelled object instance.</p>
</td>
</tr>
<tr>
<td>
<code>resources</code></br>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Scopes the template to given API Resources.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <code>gen-crd-api-reference-docs</code>
</em></p>
