---
title: Verrazzano Managed Cluster
weight: 3
aliases:
  - /docs/reference/api/vco-clusters-v1alpha1
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
<a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedCluster">VerrazzanoManagedCluster</a>
</li></ul>
<h3 id="clusters.verrazzano.io/v1alpha1.VerrazzanoManagedCluster">VerrazzanoManagedCluster
</h3>
<div>
<p>VerrazzanoManagedCluster specifies the Verrazzano Managed Cluster API.</p>
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
<td><code>VerrazzanoManagedCluster</code></td>
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
<a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedClusterSpec">
VerrazzanoManagedClusterSpec
</a>
</em>
</td>
<td>
<p>The desired state of a Verrazzano Managed Cluster resource.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>caSecret</code><br/>
<em>
string
</em>
</td>
<td>
<p>The name of a Secret that contains the CA certificate of the managed cluster. This is used to configure the
admin cluster to scrape metrics from the Prometheus endpoint on the managed cluster. If Rancher is enabled on
the admin cluster, this will be automatically populated by Verrazzano. Otherwise, if you disabled Rancher, see the pre-registration
<a href="../../../docs/setup/mc-install/advanced-mc-install/#preregistration-setup">instructions</a>
for how to create this Secret.</p>
</td>
</tr>
<tr>
<td>
<code>description</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The description of the managed cluster.</p>
</td>
</tr>
<tr>
<td>
<code>managedClusterManifestSecret</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the Secret containing the generated YAML manifest file to be applied by the user to the managed cluster.
This field is managed by a Verrazzano Kubernetes operator.</p>
</td>
</tr>
<tr>
<td>
<code>serviceAccount</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the ServiceAccount that was generated for the managed cluster. This field is managed by a
Verrazzano Kubernetes operator.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedClusterStatus">
VerrazzanoManagedClusterStatus
</a>
</em>
</td>
<td>
<p>The observed state of a Verrazzano Managed Cluster resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.ArgoCDRegistration">ArgoCDRegistration
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedClusterStatus">VerrazzanoManagedClusterStatus</a>)
</p>
<div>
<p>ArgoCDRegistration defines the Argo CD registration state for a managed cluster.</p>
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
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ArgoCDRegistrationStatus">
ArgoCDRegistrationStatus
</a>
</em>
</td>
<td>
<p>The status of the ArgoCD registration.</p>
</td>
</tr>
<tr>
<td>
<code>lastSetTimestamp</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The timestamp of last status set.</p>
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
<p>Supporting message related to the Argo CD registration status.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.ArgoCDRegistrationStatus">ArgoCDRegistrationStatus
(<code>string</code> alias)</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.ArgoCDRegistration">ArgoCDRegistration</a>)
</p>
<div>
<p>ArgoCDRegistrationStatus identifies the status of an Argo CD registration.</p>
</div>
<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody><tr><td><p>&#34;Completed&#34;</p></td>
<td></td>
</tr><tr><td><p>&#34;Failed&#34;</p></td>
<td></td>
</tr><tr><td><p>&#34;PendingRancherClusterRegistration&#34;</p></td>
<td></td>
</tr></tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.Condition">Condition
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedClusterStatus">VerrazzanoManagedClusterStatus</a>)
</p>
<div>
<p>Condition describes a condition that occurred on the Verrazzano Managed Cluster.</p>
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
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
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
<p>The condition of the multicluster resource which can be checked with a <code>kubectl wait</code> command. Condition values
are case-sensitive and formatted as follows: <code>Ready</code>: the VerrazzanoManagedCluster is ready to be used and all
resources needed have been generated.</p>
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
<p>ConditionType identifies the condition of the Verrazzano Managed Cluster which can be checked with <code>kubectl wait</code>.</p>
</div>
<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody><tr><td><p>&#34;ManagedCARetrieved&#34;</p></td>
<td><p>ManagedCARetrieved = true means that the managed cluster CA cert has been retrieved and
populated. This is done by the VMC controller via the Rancher API proxy for the managed cluster.</p>
</td>
</tr><tr><td><p>&#34;ManifestPushed&#34;</p></td>
<td><p>ConditionManifestPushed = true means the the agent and registration secrets have been successfully transferred
to the managed cluster on a multicluster install</p>
</td>
</tr><tr><td><p>&#34;Ready&#34;</p></td>
<td><p>Ready = true means the VMC is ready to be used and all resources needed have been generated</p>
</td>
</tr></tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.RancherRegistration">RancherRegistration
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedClusterStatus">VerrazzanoManagedClusterStatus</a>)
</p>
<div>
<p>RancherRegistration defines the Rancher registration state for a managed cluster.</p>
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
<code>clusterID</code><br/>
<em>
string
</em>
</td>
<td>
<p>The Rancher cluster ID for this cluster.</p>
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
<p>A supporting message related to the Rancher registration status.</p>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.RancherRegistrationStatus">
RancherRegistrationStatus
</a>
</em>
</td>
<td>
<p>The status of the Rancher registration.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.RancherRegistrationStatus">RancherRegistrationStatus
(<code>string</code> alias)</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.RancherRegistration">RancherRegistration</a>)
</p>
<div>
<p>RancherRegistrationStatus identifies the status of a Rancher registration.</p>
</div>
<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody><tr><td><p>&#34;DeleteFailed&#34;</p></td>
<td></td>
</tr><tr><td><p>&#34;Completed&#34;</p></td>
<td></td>
</tr><tr><td><p>&#34;Failed&#34;</p></td>
<td></td>
</tr></tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.StateType">StateType
(<code>string</code> alias)</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedClusterStatus">VerrazzanoManagedClusterStatus</a>)
</p>
<div>
<p>StateType identifies the state of the Verrazzano Managed Cluster.</p>
</div>
<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody><tr><td><p>&#34;Active&#34;</p></td>
<td></td>
</tr><tr><td><p>&#34;Inactive&#34;</p></td>
<td></td>
</tr><tr><td><p>&#34;Pending&#34;</p></td>
<td></td>
</tr></tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.VerrazzanoManagedClusterSpec">VerrazzanoManagedClusterSpec
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedCluster">VerrazzanoManagedCluster</a>)
</p>
<div>
<p>VerrazzanoManagedClusterSpec defines the desired state of a Verrazzano Managed Cluster.</p>
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
<code>caSecret</code><br/>
<em>
string
</em>
</td>
<td>
<p>The name of a Secret that contains the CA certificate of the managed cluster. This is used to configure the
admin cluster to scrape metrics from the Prometheus endpoint on the managed cluster. If Rancher is enabled on
the admin cluster, this will be automatically populated by Verrazzano. Otherwise, if you disabled Rancher, see the pre-registration
<a href="../../../docs/setup/mc-install/advanced-mc-install/#preregistration-setup">instructions</a>
for how to create this Secret.</p>
</td>
</tr>
<tr>
<td>
<code>description</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The description of the managed cluster.</p>
</td>
</tr>
<tr>
<td>
<code>managedClusterManifestSecret</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the Secret containing the generated YAML manifest file to be applied by the user to the managed cluster.
This field is managed by a Verrazzano Kubernetes operator.</p>
</td>
</tr>
<tr>
<td>
<code>serviceAccount</code><br/>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the ServiceAccount that was generated for the managed cluster. This field is managed by a
Verrazzano Kubernetes operator.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.VerrazzanoManagedClusterStatus">VerrazzanoManagedClusterStatus
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedCluster">VerrazzanoManagedCluster</a>)
</p>
<div>
<p>VerrazzanoManagedClusterStatus defines the observed state of a Verrazzano Managed Cluster.</p>
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
<code>apiUrl</code><br/>
<em>
string
</em>
</td>
<td>
<p>The Verrazzano API server URL for this managed cluster.</p>
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
<p>The current state of this managed cluster.</p>
</td>
</tr>
<tr>
<td>
<code>lastAgentConnectTime</code><br/>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
</em>
</td>
<td>
<p>The last time the agent from this managed cluster connected to the admin cluster.</p>
</td>
</tr>
<tr>
<td>
<code>prometheusHost</code><br/>
<em>
string
</em>
</td>
<td>
<p>The Prometheus host for this managed cluster.</p>
</td>
</tr>
<tr>
<td>
<code>thanosQueryStore</code><br/>
<em>
string
</em>
</td>
<td>
<p>The Thanos Query Store API host name for this managed cluster.</p>
</td>
</tr>
<tr>
<td>
<code>rancherRegistration</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.RancherRegistration">
RancherRegistration
</a>
</em>
</td>
<td>
<p>The state of Rancher registration for this managed cluster.</p>
</td>
</tr>
<tr>
<td>
<code>argoCDRegistration</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ArgoCDRegistration">
ArgoCDRegistration
</a>
</em>
</td>
<td>
<p>The state of ArgoCD registration for this managed cluster.</p>
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
<p>The state of this managed cluster.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <code>gen-crd-api-reference-docs</code>
on git commit <code>fd0b6edc0</code>.
</em></p>





