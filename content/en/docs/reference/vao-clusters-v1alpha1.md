---
title: Multicluster and Verrazzano Project
weight: 1
aliases:
  - /docs/reference/api/vao-clusters-v1alpha1
---
<p>Packages:</p>
<ul>
<li>
<a href="#clusters.verrazzano.io%2fv1alpha1">clusters.verrazzano.io/v1alpha1</a>
</li>
</ul>
<h2 id="clusters.verrazzano.io/v1alpha1">clusters.verrazzano.io/v1alpha1</h2>
<div>
</div>
Resource Types:
<ul><li>
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfiguration">MultiClusterApplicationConfiguration</a>
</li><li>
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterComponent">MultiClusterComponent</a>
</li><li>
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterConfigMap">MultiClusterConfigMap</a>
</li><li>
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterSecret">MultiClusterSecret</a>
</li><li>
<a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoProject">VerrazzanoProject</a>
</li></ul>
<h3 id="clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfiguration">MultiClusterApplicationConfiguration
</h3>
<div>
<p>MultiClusterApplicationConfiguration specifies the multicluster application API.</p>
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
clusters.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>MultiClusterApplicationConfiguration</code></td>
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
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfigurationSpec">
MultiClusterApplicationConfigurationSpec
</a>
</em>
</td>
<td>
<p>The desired state of a multicluster application resource.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters in which the application is to be created.</p>
</td>
</tr>
<tr>
<td>
<code>secrets</code><br/>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>List of secrets used by the application. These secrets must be created in the application’s namespace before
deploying a MultiClusterApplicationConfiguration resource.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ApplicationConfigurationTemplate">
ApplicationConfigurationTemplate
</a>
</em>
</td>
<td>
<p>Template containing the metadata and spec for an OAM applicationConfiguration resource.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterResourceStatus">
MultiClusterResourceStatus
</a>
</em>
</td>
<td>
<p>The observed state of a multicluster application resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.MultiClusterComponent">MultiClusterComponent
</h3>
<div>
<p>MultiClusterComponent specifies the MultiCluster Component API.</p>
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
clusters.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>MultiClusterComponent</code></td>
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
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterComponentSpec">
MultiClusterComponentSpec
</a>
</em>
</td>
<td>
<p>The desired state of a MultiCluster Component resource.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters in which the component is to be created.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ComponentTemplate">
ComponentTemplate
</a>
</em>
</td>
<td>
<p>Template containing the metadata and spec for an OAM component.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterResourceStatus">
MultiClusterResourceStatus
</a>
</em>
</td>
<td>
<p>The observed state of a MultiCluster Component resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.MultiClusterConfigMap">MultiClusterConfigMap
</h3>
<div>
<p>MultiClusterConfigMap specifies the MultiCluster ConfigMap API.</p>
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
clusters.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>MultiClusterConfigMap</code></td>
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
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterConfigMapSpec">
MultiClusterConfigMapSpec
</a>
</em>
</td>
<td>
<p>The desired state of a MultiCluster ConfigMap resource.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters in which the ConfigMap is to be created.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ConfigMapTemplate">
ConfigMapTemplate
</a>
</em>
</td>
<td>
<p>The embedded Kubernetes ConfigMap.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterResourceStatus">
MultiClusterResourceStatus
</a>
</em>
</td>
<td>
<p>The observed state of a MultiCluster ConfigMap resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.MultiClusterSecret">MultiClusterSecret
</h3>
<div>
<p>MultiClusterSecret specifies the MultiCluster Secret API.</p>
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
clusters.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>MultiClusterSecret</code></td>
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
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterSecretSpec">
MultiClusterSecretSpec
</a>
</em>
</td>
<td>
<p>The desired state of a MultiCluster Secret resource.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters in which the secret is to be created.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.SecretTemplate">
SecretTemplate
</a>
</em>
</td>
<td>
<p>The embedded Kubernetes secret.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterResourceStatus">
MultiClusterResourceStatus
</a>
</em>
</td>
<td>
<p>The observed state of a MultiCluster Secret resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.VerrazzanoProject">VerrazzanoProject
</h3>
<div>
<p>VerrazzanoProject specifies the Verrazzano Projects API.</p>
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
clusters.verrazzano.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br/>
string
</td>
<td><code>VerrazzanoProject</code></td>
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
<a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoProjectSpec">
VerrazzanoProjectSpec
</a>
</em>
</td>
<td>
<p>The desired state of a Verrazzano Project resource.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters on which the namespaces are to be created.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ProjectTemplate">
ProjectTemplate
</a>
</em>
</td>
<td>
<p>The project template.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.MultiClusterResourceStatus">
MultiClusterResourceStatus
</a>
</em>
</td>
<td>
<p>The observed state of a Verrazzano Project resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.ApplicationConfigurationTemplate">ApplicationConfigurationTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfigurationSpec">MultiClusterApplicationConfigurationSpec</a>)
</p>
<div>
<p>ApplicationConfigurationTemplate has the metadata and embedded spec of the OAM applicationConfiguration resource.</p>
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
<a href="#clusters.verrazzano.io/v1alpha1.EmbeddedObjectMeta">
EmbeddedObjectMeta
</a>
</em>
</td>
<td>
<p>Metadata describing the application.</p>
</td>
</tr>
<tr>
<td>
<code>spec</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/oam-kubernetes-runtime/apis/core/v1alpha2#ApplicationConfigurationSpec">
OAM core/v1alpha2.ApplicationConfigurationSpec
</a>
</em>
</td>
<td>
<p>The embedded OAM application specification.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>components</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/oam-kubernetes-runtime/apis/core/v1alpha2#ApplicationConfigurationComponent">
[]OAM core/v1alpha2.ApplicationConfigurationComponent
</a>
</em>
</td>
<td>
<p>Components of which this ApplicationConfiguration consists. Each
component will be used to instantiate a workload.</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.Cluster">Cluster
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.Placement">Placement</a>)
</p>
<div>
<p>Cluster contains the name of a single cluster.</p>
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
<p>The name of a cluster.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.ClusterLevelStatus">ClusterLevelStatus
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterResourceStatus">MultiClusterResourceStatus</a>)
</p>
<div>
<p>ClusterLevelStatus describes the status of the multicluster resource in a specific cluster.</p>
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
<code>lastUpdateTime</code><br/>
<em>
string
</em>
</td>
<td>
<p>Last update time of the resource state in this cluster.</p>
</td>
</tr>
<tr>
<td>
<code>message</code><br/>
<em>
string
</em>
</td>
<td>
<p>Message details about the status in this cluster.</p>
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
<p>Name of the cluster.</p>
</td>
</tr>
<tr>
<td>
<code>state</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.StateType">
StateType
</a>
</em>
</td>
<td>
<p>State of the resource in this cluster.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.ComponentTemplate">ComponentTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterComponentSpec">MultiClusterComponentSpec</a>)
</p>
<div>
<p>ComponentTemplate has the metadata and embedded spec of the OAM component.</p>
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
<a href="#clusters.verrazzano.io/v1alpha1.EmbeddedObjectMeta">
EmbeddedObjectMeta
</a>
</em>
</td>
<td>
<p>Metadata describing the component.</p>
</td>
</tr>
<tr>
<td>
<code>spec</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/oam-kubernetes-runtime/apis/core/v1alpha2#ComponentSpec">
OAM core/v1alpha2.ComponentSpec
</a>
</em>
</td>
<td>
<p>The embedded OAM component specification.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>workload</code><br/>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#RawExtension">
Kubernetes runtime.RawExtension
</a>
</em>
</td>
<td>
<p>A Workload that will be created for each ApplicationConfiguration that
includes this Component. Workload is an instance of a workloadDefinition.
We either use the GVK info or a special &ldquo;type&rdquo; field in the workload to associate
the content of the workload with its workloadDefinition</p>
</td>
</tr>
<tr>
<td>
<code>parameters</code><br/>
<em>
<a href="https://pkg.go.dev/github.com/crossplane/oam-kubernetes-runtime/apis/core/v1alpha2#ComponentParameter">
[]OAM core/v1alpha2.ComponentParameter
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Parameters exposed by this component. ApplicationConfigurations that
reference this component may specify values for these parameters, which
will in turn be injected into the embedded workload.</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.Condition">Condition
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterResourceStatus">MultiClusterResourceStatus</a>)
</p>
<div>
<p>Condition describes current state of a multicluster resource.</p>
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
<code>lastTransitionTime</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Last time the condition transitioned from one status to another.</p>
</td>
</tr>
<tr>
<td>
<code>message</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>A message with details about the last transition.</p>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
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
<code>type</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ConditionType">
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
<h3 id="clusters.verrazzano.io/v1alpha1.ConditionType">ConditionType
(<code>string</code> alias)</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.Condition">Condition</a>)
</p>
<div>
<p>ConditionType identifies the condition of the multicluster resource which can be checked with <code>kubectl wait</code>.</p>
</div>
<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody><tr><td><p>&#34;DeployComplete&#34;</p></td>
<td><p>DeployComplete means deployment to the specified cluster completed successfully.</p>
</td>
</tr><tr><td><p>&#34;DeployFailed&#34;</p></td>
<td><p>DeployFailed means the deployment to the specified cluster has failed.</p>
</td>
</tr><tr><td><p>&#34;DeployPending&#34;</p></td>
<td><p>DeployPending means deployment to the specified cluster is in progress.</p>
</td>
</tr></tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.ConfigMapTemplate">ConfigMapTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterConfigMapSpec">MultiClusterConfigMapSpec</a>)
</p>
<div>
<p>ConfigMapTemplate has the metadata and spec of the Kubernetes ConfigMap.</p>
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
<code>binaryData</code><br/>
<em>
map[string][]byte
</em>
</td>
<td>
<p>Corresponds to the <code>binaryData</code> field of the <code>struct</code> ConfigMap defined in
<a href="https://github.com/kubernetes/api/blob/master/core/v1/types.go">types.go</a>.</p>
</td>
</tr>
<tr>
<td>
<code>data</code><br/>
<em>
map[string]string
</em>
</td>
<td>
<p>Corresponds to the <code>data</code> field of the <code>struct</code> ConfigMap defined in
<a href="https://github.com/kubernetes/api/blob/master/core/v1/types.go">types.go</a>.</p>
</td>
</tr>
<tr>
<td>
<code>immutable</code><br/>
<em>
bool
</em>
</td>
<td>
<p>Corresponds to the <code>immutable</code> field of the <code>struct</code> ConfigMap defined in
<a href="https://github.com/kubernetes/api/blob/master/core/v1/types.go">types.go</a>.</p>
</td>
</tr>
<tr>
<td>
<code>metadata</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.EmbeddedObjectMeta">
EmbeddedObjectMeta
</a>
</em>
</td>
<td>
<p>Metadata describing the ConfigMap.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.EmbeddedObjectMeta">EmbeddedObjectMeta
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.ApplicationConfigurationTemplate">ApplicationConfigurationTemplate</a>, <a href="#clusters.verrazzano.io/v1alpha1.ComponentTemplate">ComponentTemplate</a>, <a href="#clusters.verrazzano.io/v1alpha1.ConfigMapTemplate">ConfigMapTemplate</a>, <a href="#clusters.verrazzano.io/v1alpha1.SecretTemplate">SecretTemplate</a>)
</p>
<div>
<p>EmbeddedObjectMeta is metadata describing a resource.</p>
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
<code>annotations</code><br/>
<em>
map[string]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Annotations for the resource.</p>
</td>
</tr>
<tr>
<td>
<code>labels</code><br/>
<em>
map[string]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Labels for the resource.</p>
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
<em>(Optional)</em>
<p>Name of the resource.</p>
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
<em>(Optional)</em>
<p>Namespace of the resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfigurationSpec">MultiClusterApplicationConfigurationSpec
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfiguration">MultiClusterApplicationConfiguration</a>)
</p>
<div>
<p>MultiClusterApplicationConfigurationSpec defines the desired state of a multicluster application.</p>
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
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters in which the application is to be created.</p>
</td>
</tr>
<tr>
<td>
<code>secrets</code><br/>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>List of secrets used by the application. These secrets must be created in the application’s namespace before
deploying a MultiClusterApplicationConfiguration resource.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ApplicationConfigurationTemplate">
ApplicationConfigurationTemplate
</a>
</em>
</td>
<td>
<p>Template containing the metadata and spec for an OAM applicationConfiguration resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.MultiClusterComponentSpec">MultiClusterComponentSpec
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterComponent">MultiClusterComponent</a>)
</p>
<div>
<p>MultiClusterComponentSpec defines the desired state of a MultiCluster Component.</p>
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
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters in which the component is to be created.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ComponentTemplate">
ComponentTemplate
</a>
</em>
</td>
<td>
<p>Template containing the metadata and spec for an OAM component.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.MultiClusterConfigMapSpec">MultiClusterConfigMapSpec
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterConfigMap">MultiClusterConfigMap</a>)
</p>
<div>
<p>MultiClusterConfigMapSpec defines the desired state of a MultiCluster ConfigMap.</p>
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
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters in which the ConfigMap is to be created.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ConfigMapTemplate">
ConfigMapTemplate
</a>
</em>
</td>
<td>
<p>The embedded Kubernetes ConfigMap.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.MultiClusterResourceStatus">MultiClusterResourceStatus
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfiguration">MultiClusterApplicationConfiguration</a>, <a href="#clusters.verrazzano.io/v1alpha1.MultiClusterComponent">MultiClusterComponent</a>, <a href="#clusters.verrazzano.io/v1alpha1.MultiClusterConfigMap">MultiClusterConfigMap</a>, <a href="#clusters.verrazzano.io/v1alpha1.MultiClusterSecret">MultiClusterSecret</a>, <a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoProject">VerrazzanoProject</a>)
</p>
<div>
<p>MultiClusterResourceStatus is the runtime status of a multicluster resource.</p>
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
<code>clusters</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ClusterLevelStatus">
[]ClusterLevelStatus
</a>
</em>
</td>
<td>
<p>Status information for each cluster.</p>
</td>
</tr>
<tr>
<td>
<code>conditions</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Condition">
[]Condition
</a>
</em>
</td>
<td>
<p>The current state of a multicluster resource.</p>
</td>
</tr>
<tr>
<td>
<code>state</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.StateType">
StateType
</a>
</em>
</td>
<td>
<p>The state of the multicluster resource. State values are case-sensitive and formatted as follows:
<ul><li><code>Failed</code>: deployment to cluster failed</li><li><code>Pending</code>: deployment to cluster is in progress</li><li><code>Succeeded</code>: deployment to cluster successfully completed</li></ul></p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.MultiClusterSecretSpec">MultiClusterSecretSpec
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterSecret">MultiClusterSecret</a>)
</p>
<div>
<p>MultiClusterSecretSpec defines the desired state of a MultiCluster Secret.</p>
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
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters in which the secret is to be created.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.SecretTemplate">
SecretTemplate
</a>
</em>
</td>
<td>
<p>The embedded Kubernetes secret.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.NamespaceTemplate">NamespaceTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.ProjectTemplate">ProjectTemplate</a>)
</p>
<div>
<p>NamespaceTemplate contains the metadata and specification of a Kubernetes namespace.</p>
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
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#namespacespec-v1-core">
Kubernetes core/v1.NamespaceSpec
</a>
</em>
</td>
<td>
<p>The specification of a namespace.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>finalizers</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#finalizername-v1-core">
[]Kubernetes core/v1.FinalizerName
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Finalizers is an opaque list of values that must be empty to permanently remove object from storage.
More info: <a href="https://kubernetes.io/docs/tasks/administer-cluster/namespaces/">https://kubernetes.io/docs/tasks/administer-cluster/namespaces/</a></p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.NetworkPolicyTemplate">NetworkPolicyTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.ProjectTemplate">ProjectTemplate</a>)
</p>
<div>
<p>NetworkPolicyTemplate contains the metadata and specification of a Kubernetes NetworkPolicy.
<div class="alert alert-warning" role="alert">
<h4 class="alert-heading">NOTE</h4>
To add an application NetworkPolicy, see <a href="../../../docs/networking/security/#networkpolicies-for-applications">NetworkPolicies for applications</a>.
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
<code>metadata</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<em>(Optional)</em>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#networkpolicyspec-v1-networking-k8s-io">
Kubernetes networking/v1.NetworkPolicySpec
</a>
</em>
</td>
<td>
<p>The specification of a network policy.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>podSelector</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<p>Selects the pods to which this NetworkPolicy object applies. The array of
ingress rules is applied to any pods selected by this field. Multiple network
policies can select the same set of pods. In this case, the ingress rules for
each are combined additively. This field is NOT optional and follows standard
label selector semantics. An empty podSelector matches all pods in this
namespace.</p>
</td>
</tr>
<tr>
<td>
<code>ingress</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#networkpolicyingressrule-v1-networking-k8s-io">
[]Kubernetes networking/v1.NetworkPolicyIngressRule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>List of ingress rules to be applied to the selected pods. Traffic is allowed to
a pod if there are no NetworkPolicies selecting the pod
(and cluster policy otherwise allows the traffic), OR if the traffic source is
the pod&rsquo;s local node, OR if the traffic matches at least one ingress rule
across all of the NetworkPolicy objects whose podSelector matches the pod. If
this field is empty then this NetworkPolicy does not allow any traffic (and serves
solely to ensure that the pods it selects are isolated by default)</p>
</td>
</tr>
<tr>
<td>
<code>egress</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#networkpolicyegressrule-v1-networking-k8s-io">
[]Kubernetes networking/v1.NetworkPolicyEgressRule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>List of egress rules to be applied to the selected pods. Outgoing traffic is
allowed if there are no NetworkPolicies selecting the pod (and cluster policy
otherwise allows the traffic), OR if the traffic matches at least one egress rule
across all of the NetworkPolicy objects whose podSelector matches the pod. If
this field is empty then this NetworkPolicy limits all outgoing traffic (and serves
solely to ensure that the pods it selects are isolated by default).
This field is beta-level in 1.8</p>
</td>
</tr>
<tr>
<td>
<code>policyTypes</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#policytype-v1-networking-k8s-io">
[]Kubernetes networking/v1.PolicyType
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>List of rule types that the NetworkPolicy relates to.
Valid options are [&ldquo;Ingress&rdquo;], [&ldquo;Egress&rdquo;], or [&ldquo;Ingress&rdquo;, &ldquo;Egress&rdquo;].
If this field is not specified, it will default based on the existence of Ingress or Egress rules;
policies that contain an Egress section are assumed to affect Egress, and all policies
(whether or not they contain an Ingress section) are assumed to affect Ingress.
If you want to write an egress-only policy, you must explicitly specify policyTypes [ &ldquo;Egress&rdquo; ].
Likewise, if you want to write a policy that specifies that no egress is allowed,
you must specify a policyTypes value that include &ldquo;Egress&rdquo; (since such a policy would not include
an Egress section and would otherwise default to just [ &ldquo;Ingress&rdquo; ]).
This field is beta-level in 1.8</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.Placement">Placement
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfigurationSpec">MultiClusterApplicationConfigurationSpec</a>, <a href="#clusters.verrazzano.io/v1alpha1.MultiClusterComponentSpec">MultiClusterComponentSpec</a>, <a href="#clusters.verrazzano.io/v1alpha1.MultiClusterConfigMapSpec">MultiClusterConfigMapSpec</a>, <a href="#clusters.verrazzano.io/v1alpha1.MultiClusterSecretSpec">MultiClusterSecretSpec</a>, <a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoProjectSpec">VerrazzanoProjectSpec</a>)
</p>
<div>
<p>Placement contains the name of each cluster where a resource will be located.</p>
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
<code>clusters</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Cluster">
[]Cluster
</a>
</em>
</td>
<td>
<p>List of clusters.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.ProjectTemplate">ProjectTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoProjectSpec">VerrazzanoProjectSpec</a>)
</p>
<div>
<p>ProjectTemplate contains the list of namespaces to create and the optional security configuration for each namespace.</p>
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
<code>namespaces</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NamespaceTemplate">
[]NamespaceTemplate
</a>
</em>
</td>
<td>
<p>The list of application namespaces to create for this project.</p>
</td>
</tr>
<tr>
<td>
<code>networkPolicies</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NetworkPolicyTemplate">
[]NetworkPolicyTemplate
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Network policies applied to namespaces in the project.</p>
</td>
</tr>
<tr>
<td>
<code>security</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.SecuritySpec">
SecuritySpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The project security configuration.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.SecretTemplate">SecretTemplate
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.MultiClusterSecretSpec">MultiClusterSecretSpec</a>)
</p>
<div>
<p>SecretTemplate has the metadata and spec of the Kubernetes Secret.</p>
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
<code>data</code><br/>
<em>
map[string][]byte
</em>
</td>
<td>
<p>Corresponds to the data field of the struct Secret defined in
<a href="https://github.com/kubernetes/api/blob/master/core/v1/types.go">types.go</a>.</p>
</td>
</tr>
<tr>
<td>
<code>metadata</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.EmbeddedObjectMeta">
EmbeddedObjectMeta
</a>
</em>
</td>
<td>
<p>Metadata describing the secret.</p>
</td>
</tr>
<tr>
<td>
<code>stringData</code><br/>
<em>
map[string]string
</em>
</td>
<td>
<p>Corresponds to the <code>stringData</code> field of the <code>struct</code> Secret defined in
<a href="https://github.com/kubernetes/api/blob/master/core/v1/types.go">types.go</a>.</p>
</td>
</tr>
<tr>
<td>
<code>type</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#secrettype-v1-core">
Kubernetes core/v1.SecretType
</a>
</em>
</td>
<td>
<p>The type of secret.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.SecuritySpec">SecuritySpec
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.ProjectTemplate">ProjectTemplate</a>)
</p>
<div>
<p>SecuritySpec defines the security configuration for a Verrazzano Project.</p>
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
<code>projectAdminSubjects</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#subject-v1-rbac-authorization-k8s-io">
[]Kubernetes rbac/v1.Subject
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The subjects to bind to the <code>verrazzano-project-admin</code> role.</p>
</td>
</tr>
<tr>
<td>
<code>projectMonitorSubjects</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#subject-v1-rbac-authorization-k8s-io">
[]Kubernetes rbac/v1.Subject
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The subjects to bind to the <code>verrazzano-project-monitoring</code> role.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.StateType">StateType
(<code>string</code> alias)</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.ClusterLevelStatus">ClusterLevelStatus</a>, <a href="#clusters.verrazzano.io/v1alpha1.MultiClusterResourceStatus">MultiClusterResourceStatus</a>)
</p>
<div>
<p>StateType identifies the state of a multicluster resource.</p>
</div>
<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody><tr><td><p>&#34;Failed&#34;</p></td>
<td><p>Failed is the state when deploy to specified cluster has failed.</p>
</td>
</tr><tr><td><p>&#34;Pending&#34;</p></td>
<td><p>Pending is the state when deploy to specified cluster is in progress.</p>
</td>
</tr><tr><td><p>&#34;Succeeded&#34;</p></td>
<td><p>Succeeded is the state when deploy to specified cluster is completed.</p>
</td>
</tr></tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.VerrazzanoProjectSpec">VerrazzanoProjectSpec
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoProject">VerrazzanoProject</a>)
</p>
<div>
<p>VerrazzanoProjectSpec defines the desired state of a Verrazzano Project.</p>
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
<code>placement</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Placement">
Placement
</a>
</em>
</td>
<td>
<p>Clusters on which the namespaces are to be created.</p>
</td>
</tr>
<tr>
<td>
<code>template</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ProjectTemplate">
ProjectTemplate
</a>
</em>
</td>
<td>
<p>The project template.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <code>gen-crd-api-reference-docs</code>
on git commit <code>3a421ac9e</code>.
</em></p>





