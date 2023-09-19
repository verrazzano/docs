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
<a href="#clusters.verrazzano.io/v1alpha1.OCNEOCIQuickCreate">OCNEOCIQuickCreate</a>
</li><li>
<a href="#clusters.verrazzano.io/v1alpha1.OKEQuickCreate">OKEQuickCreate</a>
</li><li>
<a href="#clusters.verrazzano.io/v1alpha1.VerrazzanoManagedCluster">VerrazzanoManagedCluster</a>
</li></ul>
<h3 id="clusters.verrazzano.io/v1alpha1.OCNEOCIQuickCreate">OCNEOCIQuickCreate
</h3>
<div>
<p>OCNEOCIQuickCreate specifies the API for quick-create OCI OCNE Clusters.</p>
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
<td><code>OCNEOCIQuickCreate</code></td>
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
<a href="#clusters.verrazzano.io/v1alpha1.OCIOCNEClusterSpec">
OCIOCNEClusterSpec
</a>
</em>
</td>
<td>
<p>The desired state of an OCNEOCIQuickCreate resource.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>identityRef</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NamespacedRef">
NamespacedRef
</a>
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec</a>.)
</p>
<p>Reference for cloud authentication.</p>
</td>
</tr>
<tr>
<td>
<code>privateRegistry</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.PrivateRegistry">
PrivateRegistry
</a>
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec</a>.)
</p>
<p>Private Registry settings for the workload cluster.</p>
</td>
</tr>
<tr>
<td>
<code>proxy</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Proxy">
Proxy
</a>
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec</a>.)
</p>
<p>HTTP Proxy settings.</p>
</td>
</tr>
<tr>
<td>
<code>kubernetes</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.KubernetesBase">
KubernetesBase
</a>
</em>
</td>
<td>
<p>Kubernetes settings.</p>
</td>
</tr>
<tr>
<td>
<code>ocne</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OCNE">
OCNE
</a>
</em>
</td>
<td>
<p>OCNE settings.</p>
</td>
</tr>
<tr>
<td>
<code>oci</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OCI">
OCI
</a>
</em>
</td>
<td>
<p>OCI infrastructure settings.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OCNEOCIQuickCreateStatus">
OCNEOCIQuickCreateStatus
</a>
</em>
</td>
<td>
<p>The observed state of an OCNEOCIQuickCreate resource.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OKEQuickCreate">OKEQuickCreate
</h3>
<div>
<p>OKEQuickCreate specifies the API for quick-create OKE Clusters.</p>
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
<td><code>OKEQuickCreate</code></td>
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
<a href="#clusters.verrazzano.io/v1alpha1.OKEQuickCreateSpec">
OKEQuickCreateSpec
</a>
</em>
</td>
<td>
<p>The desired state of an OCNEOCIQuickCreate resource.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>identityRef</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NamespacedRef">
NamespacedRef
</a>
</em>
</td>
<td>
<p>Reference for cloud authentication.</p>
</td>
</tr>
<tr>
<td>
<code>kubernetes</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Kubernetes">
Kubernetes
</a>
</em>
</td>
<td>
<p>Kubernetes settings.</p>
</td>
</tr>
<tr>
<td>
<code>oke</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OKE">
OKE
</a>
</em>
</td>
<td>
<p>OKE Cluster settings.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OKEQuickCreateStatus">
OKEQuickCreateStatus
</a>
</em>
</td>
<td>
<p>The observed state of an OCNEOCIQuickCreate resource.</p>
</td>
</tr>
</tbody>
</table>
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
<h3 id="clusters.verrazzano.io/v1alpha1.CNIType">CNIType
(<code>string</code> alias)</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OKENetwork">OKENetwork</a>)
</p>
<div>
</div>
<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody><tr><td><p>&#34;FLANNEL_OVERLAY&#34;</p></td>
<td></td>
</tr><tr><td><p>&#34;OCI_VCN_IP_NATIVE&#34;</p></td>
<td></td>
</tr></tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.ClusterNetwork">ClusterNetwork
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.Kubernetes">Kubernetes</a>, <a href="#clusters.verrazzano.io/v1alpha1.KubernetesBase">KubernetesBase</a>)
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
<code>podCIDR</code><br/>
<em>
string
</em>
</td>
<td>
<p>IP range for Kubernetes pods.
The default is <code>10.244.0.0/16</code></p>
</td>
</tr>
<tr>
<td>
<code>serviceCIDR</code><br/>
<em>
string
</em>
</td>
<td>
<p>IP range for Kubernetes service addresses.
The default is <code>10.96.0.0/16</code>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec
</h3>
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
<code>identityRef</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NamespacedRef">
NamespacedRef
</a>
</em>
</td>
<td>
<p>Reference for cloud authentication.</p>
</td>
</tr>
<tr>
<td>
<code>privateRegistry</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.PrivateRegistry">
PrivateRegistry
</a>
</em>
</td>
<td>
<p>Private Registry settings for the workload cluster.</p>
</td>
</tr>
<tr>
<td>
<code>proxy</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Proxy">
Proxy
</a>
</em>
</td>
<td>
<p>HTTP Proxy settings.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI
</h3>
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
<code>region</code><br/>
<em>
string
</em>
</td>
<td>
<p>OCI region where the cluster will be created.</p>
</td>
</tr>
<tr>
<td>
<code>compartment</code><br/>
<em>
string
</em>
</td>
<td>
<p>OCI Compartment OCID where the cluster will be created</p>
</td>
</tr>
<tr>
<td>
<code>sshPublicKey</code><br/>
<em>
string
</em>
</td>
<td>
<p>SSH public key for node ssh.</p>
</td>
</tr>
<tr>
<td>
<code>imageId</code><br/>
<em>
string
</em>
</td>
<td>
<p>Node image OCID.
The default is the latest OL8 image in the provided compartment.</p>
</td>
</tr>
<tr>
<td>
<code>cloudInitScript</code><br/>
<em>
[]string
</em>
</td>
<td>
<p>Cloud-init script to run during node startup.</p>
</td>
</tr>
</tbody>
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
<h3 id="clusters.verrazzano.io/v1alpha1.Kubernetes">Kubernetes
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OKEQuickCreateSpec">OKEQuickCreateSpec</a>)
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
<code>version</code><br/>
<em>
string
</em>
</td>
<td>
<p>Kubernetes version.</p>
</td>
</tr>
<tr>
<td>
<code>clusterNetwork</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ClusterNetwork">
ClusterNetwork
</a>
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.KubernetesBase">KubernetesBase</a>.)
</p>
<p>Kubernetes network settings.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.KubernetesBase">KubernetesBase
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCIOCNEClusterSpec">OCIOCNEClusterSpec</a>)
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
<code>clusterNetwork</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.ClusterNetwork">
ClusterNetwork
</a>
</em>
</td>
<td>
<p>Kubernetes network settings.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.NamedOCINode">NamedOCINode
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCI">OCI</a>, <a href="#clusters.verrazzano.io/v1alpha1.OKE">OKE</a>)
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
<code>name</code><br/>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>shape</code><br/>
<em>
string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.OCINode">OCINode</a>.)
</p>
<p>Node pool Shape.</p>
</td>
</tr>
<tr>
<td>
<code>ocpus</code><br/>
<em>
int
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.OCINode">OCINode</a>.)
</p>
<p>Number of OCPUs per node, when using flex shapes.</p>
</td>
</tr>
<tr>
<td>
<code>memoryGbs</code><br/>
<em>
int
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.OCINode">OCINode</a>.)
</p>
<p>Amount of memory per node, in gigabytes, when using flex shapes.</p>
</td>
</tr>
<tr>
<td>
<code>bootVolumeGbs</code><br/>
<em>
int
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.OCINode">OCINode</a>.)
</p>
<p>Size of node boot volume, in gigabytes.</p>
</td>
</tr>
<tr>
<td>
<code>replicas</code><br/>
<em>
int
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.OCINode">OCINode</a>.)
</p>
<p>Number of nodes to create.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.NamespacedRef">NamespacedRef
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec</a>, <a href="#clusters.verrazzano.io/v1alpha1.OCIOCNEClusterSpec">OCIOCNEClusterSpec</a>, <a href="#clusters.verrazzano.io/v1alpha1.OKEQuickCreateSpec">OKEQuickCreateSpec</a>, <a href="#clusters.verrazzano.io/v1alpha1.PrivateRegistry">PrivateRegistry</a>)
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
<code>name</code><br/>
<em>
string
</em>
</td>
<td>
<p>Name of the ref.</p>
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
<p>Namespace of the ref.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.Network">Network
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCI">OCI</a>, <a href="#clusters.verrazzano.io/v1alpha1.OKENetwork">OKENetwork</a>)
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
<code>createVCN</code><br/>
<em>
bool
</em>
</td>
<td>
<p>If true, a new VCN is created for the cluster.
The default is false.</p>
</td>
</tr>
<tr>
<td>
<code>vcn</code><br/>
<em>
string
</em>
</td>
<td>
<p>OCID of an existing VCN to create the cluster inside.</p>
</td>
</tr>
<tr>
<td>
<code>subnets</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Subnet">
[]Subnet
</a>
</em>
</td>
<td>
<p>List of existing subnets that will be used by the cluster.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OCI">OCI
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCIOCNEClusterSpec">OCIOCNEClusterSpec</a>)
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
<code>region</code><br/>
<em>
string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>OCI region where the cluster will be created.</p>
</td>
</tr>
<tr>
<td>
<code>compartment</code><br/>
<em>
string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>OCI Compartment OCID where the cluster will be created</p>
</td>
</tr>
<tr>
<td>
<code>sshPublicKey</code><br/>
<em>
string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>SSH public key for node ssh.</p>
</td>
</tr>
<tr>
<td>
<code>imageId</code><br/>
<em>
string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>Node image OCID.
The default is the latest OL8 image in the provided compartment.</p>
</td>
</tr>
<tr>
<td>
<code>cloudInitScript</code><br/>
<em>
[]string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>Cloud-init script to run during node startup.</p>
</td>
</tr>
<tr>
<td>
<code>controlPlane</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OCINode">
OCINode
</a>
</em>
</td>
<td>
<p>Control Plane node settings.</p>
</td>
</tr>
<tr>
<td>
<code>workers</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NamedOCINode">
[]NamedOCINode
</a>
</em>
</td>
<td>
<p>List of worker nodes.</p>
</td>
</tr>
<tr>
<td>
<code>network</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Network">
Network
</a>
</em>
</td>
<td>
<p>OCI Network settings.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OCINode">OCINode
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCI">OCI</a>)
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
<code>shape</code><br/>
<em>
string
</em>
</td>
<td>
<p>Node pool Shape.</p>
</td>
</tr>
<tr>
<td>
<code>ocpus</code><br/>
<em>
int
</em>
</td>
<td>
<p>Number of OCPUs per node, when using flex shapes.</p>
</td>
</tr>
<tr>
<td>
<code>memoryGbs</code><br/>
<em>
int
</em>
</td>
<td>
<p>Amount of memory per node, in gigabytes, when using flex shapes.</p>
</td>
</tr>
<tr>
<td>
<code>bootVolumeGbs</code><br/>
<em>
int
</em>
</td>
<td>
<p>Size of node boot volume, in gigabytes.</p>
</td>
</tr>
<tr>
<td>
<code>replicas</code><br/>
<em>
int
</em>
</td>
<td>
<p>Number of nodes to create.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OCIOCNEClusterSpec">OCIOCNEClusterSpec
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCNEOCIQuickCreate">OCNEOCIQuickCreate</a>)
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
<code>identityRef</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NamespacedRef">
NamespacedRef
</a>
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec</a>.)
</p>
<p>Reference for cloud authentication.</p>
</td>
</tr>
<tr>
<td>
<code>privateRegistry</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.PrivateRegistry">
PrivateRegistry
</a>
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec</a>.)
</p>
<p>Private Registry settings for the workload cluster.</p>
</td>
</tr>
<tr>
<td>
<code>proxy</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Proxy">
Proxy
</a>
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec</a>.)
</p>
<p>HTTP Proxy settings.</p>
</td>
</tr>
<tr>
<td>
<code>kubernetes</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.KubernetesBase">
KubernetesBase
</a>
</em>
</td>
<td>
<p>Kubernetes settings.</p>
</td>
</tr>
<tr>
<td>
<code>ocne</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OCNE">
OCNE
</a>
</em>
</td>
<td>
<p>OCNE settings.</p>
</td>
</tr>
<tr>
<td>
<code>oci</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OCI">
OCI
</a>
</em>
</td>
<td>
<p>OCI infrastructure settings.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OCNE">OCNE
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCIOCNEClusterSpec">OCIOCNEClusterSpec</a>)
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
<code>version</code><br/>
<em>
string
</em>
</td>
<td>
<p>OCNE Version.</p>
</td>
</tr>
<tr>
<td>
<code>dependencies</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OCNEDependencies">
OCNEDependencies
</a>
</em>
</td>
<td>
<p>OCNE dependency settings.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OCNEDependencies">OCNEDependencies
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCNE">OCNE</a>)
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
<code>skipInstall</code><br/>
<em>
bool
</em>
</td>
<td>
<p>Whether to skip OCNE dependency installation.
The default is <code>false</code>.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OCNEOCIQuickCreateStatus">OCNEOCIQuickCreateStatus
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCNEOCIQuickCreate">OCNEOCIQuickCreate</a>)
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
<code>phase</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.QuickCreatePhase">
QuickCreatePhase
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OKE">OKE
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OKEQuickCreateSpec">OKEQuickCreateSpec</a>)
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
<code>region</code><br/>
<em>
string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>OCI region where the cluster will be created.</p>
</td>
</tr>
<tr>
<td>
<code>compartment</code><br/>
<em>
string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>OCI Compartment OCID where the cluster will be created</p>
</td>
</tr>
<tr>
<td>
<code>sshPublicKey</code><br/>
<em>
string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>SSH public key for node ssh.</p>
</td>
</tr>
<tr>
<td>
<code>imageId</code><br/>
<em>
string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>Node image OCID.
The default is the latest OL8 image in the provided compartment.</p>
</td>
</tr>
<tr>
<td>
<code>cloudInitScript</code><br/>
<em>
[]string
</em>
</td>
<td>
<p>
(Inlined from <a href="#clusters.verrazzano.io/v1alpha1.CommonOCI">CommonOCI</a>.)
</p>
<p>Cloud-init script to run during node startup.</p>
</td>
</tr>
<tr>
<td>
<code>nodePools</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NamedOCINode">
[]NamedOCINode
</a>
</em>
</td>
<td>
<p>List of Node pools.</p>
</td>
</tr>
<tr>
<td>
<code>virtualNodePools</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.VirtualNodePool">
[]VirtualNodePool
</a>
</em>
</td>
<td>
<p>List of Virtual Node pools.</p>
</td>
</tr>
<tr>
<td>
<code>network</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OKENetwork">
OKENetwork
</a>
</em>
</td>
<td>
<p>Network settings for the OKE Cluster.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OKENetwork">OKENetwork
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OKE">OKE</a>)
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
<code>config</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Network">
Network
</a>
</em>
</td>
<td>
<p>VCN and subnet settings for existing networks.</p>
</td>
</tr>
<tr>
<td>
<code>cniType</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.CNIType">
CNIType
</a>
</em>
</td>
<td>
<p>CNI Type for cluster networking. May be FLANNEL_OVERLAY or OCI_VCN_IP_NATIVE.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OKEQuickCreateSpec">OKEQuickCreateSpec
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OKEQuickCreate">OKEQuickCreate</a>)
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
<code>identityRef</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NamespacedRef">
NamespacedRef
</a>
</em>
</td>
<td>
<p>Reference for cloud authentication.</p>
</td>
</tr>
<tr>
<td>
<code>kubernetes</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.Kubernetes">
Kubernetes
</a>
</em>
</td>
<td>
<p>Kubernetes settings.</p>
</td>
</tr>
<tr>
<td>
<code>oke</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.OKE">
OKE
</a>
</em>
</td>
<td>
<p>OKE Cluster settings.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.OKEQuickCreateStatus">OKEQuickCreateStatus
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OKEQuickCreate">OKEQuickCreate</a>)
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
<code>phase</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.QuickCreatePhase">
QuickCreatePhase
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.PrivateRegistry">PrivateRegistry
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec</a>, <a href="#clusters.verrazzano.io/v1alpha1.OCIOCNEClusterSpec">OCIOCNEClusterSpec</a>)
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
<code>url</code><br/>
<em>
string
</em>
</td>
<td>
<p>Private registry URL.</p>
</td>
</tr>
<tr>
<td>
<code>credentialSecret</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.NamespacedRef">
NamespacedRef
</a>
</em>
</td>
<td>
<p>Reference to private registry credentials secret.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.Proxy">Proxy
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.CommonClusterSpec">CommonClusterSpec</a>, <a href="#clusters.verrazzano.io/v1alpha1.OCIOCNEClusterSpec">OCIOCNEClusterSpec</a>)
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
<code>httpProxy</code><br/>
<em>
string
</em>
</td>
<td>
<p>HTTP Proxy string.</p>
</td>
</tr>
<tr>
<td>
<code>httpsProxy</code><br/>
<em>
string
</em>
</td>
<td>
<p>HTTPS Proxy string.</p>
</td>
</tr>
<tr>
<td>
<code>noProxy</code><br/>
<em>
string
</em>
</td>
<td>
<p>No Proxy string.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.QuickCreatePhase">QuickCreatePhase
(<code>string</code> alias)</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OCNEOCIQuickCreateStatus">OCNEOCIQuickCreateStatus</a>, <a href="#clusters.verrazzano.io/v1alpha1.OKEQuickCreateStatus">OKEQuickCreateStatus</a>)
</p>
<div>
</div>
<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody><tr><td><p>&#34;Complete&#34;</p></td>
<td><p>QuickCreatePhaseComplete means the Quick Create has finished. Quick Create CR cleanup is started once this phase is reached.</p>
</td>
</tr><tr><td><p>&#34;Provisioning&#34;</p></td>
<td><p>QuickCreatePhaseProvisioning means the Quick Create is in progress.</p>
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
<h3 id="clusters.verrazzano.io/v1alpha1.Subnet">Subnet
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.Network">Network</a>)
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
<code>role</code><br/>
<em>
<a href="#clusters.verrazzano.io/v1alpha1.SubnetRole">
SubnetRole
</a>
</em>
</td>
<td>
<p>Role of subnet within the cluster.</p>
</td>
</tr>
<tr>
<td>
<code>id</code><br/>
<em>
string
</em>
</td>
<td>
<p>The ID of the subnet.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="clusters.verrazzano.io/v1alpha1.SubnetRole">SubnetRole
(<code>string</code> alias)</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.Subnet">Subnet</a>)
</p>
<div>
</div>
<table>
<thead>
<tr>
<th>Value</th>
<th>Description</th>
</tr>
</thead>
<tbody><tr><td><p>&#34;control-plane&#34;</p></td>
<td><p>SubnetRoleControlPlane is the role of the Control Plane subnet.</p>
</td>
</tr><tr><td><p>&#34;control-plane-endpoint&#34;</p></td>
<td><p>SubnetRoleControlPlaneEndpoint is the role of the Control Plane endpoint subnet.</p>
</td>
</tr><tr><td><p>&#34;service-lb&#34;</p></td>
<td><p>SubnetRoleServiceLB is the role of the load balancer subnet.</p>
</td>
</tr><tr><td><p>&#34;worker&#34;</p></td>
<td><p>SubnetRoleWorker is the role of the worker subnet.</p>
</td>
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
<h3 id="clusters.verrazzano.io/v1alpha1.VirtualNodePool">VirtualNodePool
</h3>
<p>
(<em>Appears on:</em><a href="#clusters.verrazzano.io/v1alpha1.OKE">OKE</a>)
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
<code>name</code><br/>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>replicas</code><br/>
<em>
int
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <code>gen-crd-api-reference-docs</code>
on git commit <code>a8aa3551b</code>.
</em></p>





