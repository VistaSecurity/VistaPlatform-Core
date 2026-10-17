# Virtualization

A **cluster** is a group of hypervisor hosts that run virtual machines together: a vSphere cluster, a Proxmox cluster, a Hyper-V cluster, a Kubernetes cluster, or one region of a cloud account. A **virtual machine** is not a separate kind of record; it is an asset of the *Virtual machine* class, and a **hypervisor** is an asset of the *Hypervisor* class. The cluster is the object that ties them together, and it is never an asset itself. A NetBox *cluster type*, *cluster group*, *cluster* and *virtual disk* map onto the objects described here one to one.

## Where to find it

| You want to | Go to |
|---|---|
| See every cluster, with its hosts, VMs and status | **Inventory → Clusters** (the *Assets* group of lenses) |
| Open one cluster | Click its name in the Clusters lens |
| Maintain cluster types and groups | **Settings → Infrastructure → Cluster Types & Groups** |
| See a VM's cluster, resources and virtual disks, or a hypervisor's hosted VMs | The **Virtual machine** or **Hypervisor** card on the asset page |

Reading needs the `virtualization.read` permission and every change needs `virtualization.manage`. Tenant Administrators and Security Administrators have both; Viewers can read. Without `virtualization.manage` the **Add**, **Edit**, **Delete** and **Approve** buttons below are not shown.

## The Clusters lens

The lens lists each cluster with its **Name**, **Type**, **Group**, **Scope**, **Hosts** and **VMs** counts and its **Status**. Filter by type with the *All types* menu or search by name with *Search clusters*. A cluster that is not yet approved carries a second chip beside its status (*Pending approval*, *Stale* and so on).

**Add cluster** asks for a name, a cluster type (required), an optional cluster group, a status and a description. The status is NetBox's list: *Planned*, *Staging*, *Active*, *Decommissioning* or *Offline*. A cluster's name is unique within its type.

If the lens is empty it says so: nothing has told the platform about a cluster and nobody has declared one.

## The cluster page

Clicking a cluster opens its page. The header shows the type, group and status chips, and (with `virtualization.manage`) **Approve** for a pending cluster, **Edit** and **Delete**. Below it:

- **Resources** — tiles for the number of virtual machines and the total vCPUs, memory and disk of the VMs in the cluster. A VM that reports no value for a resource is left out of the total, and the tile says how many VMs report it (for example "4 of 6 VMs report it"); an unknown value is shown as a dash, never as zero.
- **Virtual machines** — each VM with its status, vCPUs, memory, disk and number of virtual disks. A VM links to its asset page.
- **Hosts** — each hypervisor in the cluster with its class, status and where the membership came from. **Add host** (a dialog titled *Add host*) lists hypervisor assets; the **x** on a row removes a host from the cluster. A host is in at most one cluster, so adding a hypervisor that is in another cluster moves it here.
- **Changes** and **Journal** tabs — who changed the cluster and when, and notes people have written on it.

**Delete** asks first. A VM that was in the deleted cluster stays in the inventory without a cluster. A cluster type that clusters still use cannot be deleted.

## Cluster types and groups

**Settings → Infrastructure → Cluster Types & Groups** has two tables.

- **Cluster types** — the technology a cluster runs. Nine types are built in and shown with a *Built in* tag, read-only: VMware vSphere, Proxmox, Hyper-V, KVM, Nutanix, AWS, Azure, GCP and Kubernetes. **Add cluster type** creates your own (a name, an optional slug, an optional description); a type you added can be edited or deleted.
- **Cluster groups** — your own grouping of clusters, for example by data centre, environment or team. **Add cluster group** works the same way.

If you leave the slug blank it is made from the name.

## Virtual machines on the asset page

Open any asset from **Inventory**. An asset that is a virtual machine shows a **Virtual machine** card; one that is a hypervisor shows a **Hypervisor** card. Other assets show neither. The cards need `virtualization.read`.

- **Virtual machine** card — the VM's **Cluster** (a link to the cluster page, with its type), its **vCPUs**, **Memory** and **Disk**, and the list of its **Virtual disks** by name and size ("None recorded" when there are none). **Edit** opens *Edit virtual machine*, where you choose the cluster (or *No cluster*) and enter vCPUs, memory in MB and disk in MB.
- **Hypervisor** card — the **Cluster** the host is in and the **Hosted VMs** recorded as running on it, each with its vCPUs and memory. "No VM is recorded as running on this host" means nothing has said so, not that the host is idle.

A VM's network adapters are ordinary [interfaces](./interfaces.md) of type *Virtual* on the VM asset, so they appear on its **Interfaces** tab and carry its IP addresses.

## How discovery fills these in

- **Cloud discovery.** Each connected cloud account and region is mirrored as one cluster of the provider's type (AWS, Azure or GCP), named `<account>/<region>`, and every compute instance found there is a virtual machine in it. The mirror exists so a cloud estate looks the same as an on-premises one, and for NetBox sync; the cluster page says so. The account itself remains the inventory object.
- **Clusters a collector reports** arrive pending approval. Open the cluster page and click **Approve** to make it active.
- **Hypervisors and their hosted VMs** are recorded by hand today: create the cluster, then use **Add host** on its page and the **Edit** button on each VM's card. The platform has no collector yet that reads a vCenter, Proxmox or Hyper-V manager and fills these in by itself.

A host's source on the cluster page tells a measured membership from one a person declared.


## Finding VMs and hosts by cluster

The inventory query language reaches the cluster with `cluster`, `cluster.type` and `cluster.group`; see [Query](../features/query.md).

## API

`/api/v2/inventory-service/virtualization/cluster-types`, `/cluster-groups`, `/clusters` and `/virtual-disks` list, create, read, change (JSON merge-patch) and delete. `GET`, `POST` and `DELETE` on `/clusters/{id}/hosts` (and `/{asset_id}`) manage a cluster's hosts, `GET /clusters/{id}/vms` lists its VMs, and `GET` and `PATCH /assets/{id}/virtualization` read and change a VM's cluster, vCPUs, memory and disk. Reads need `virtualization.read`, writes `virtualization.manage`. Virtual disks are created through the API; the asset page shows them but has no button to add one.
