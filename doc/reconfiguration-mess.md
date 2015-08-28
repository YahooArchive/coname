`etcd/raft` is sufficiently different from the "dissertation" raft that
reconfiguration algorithms do not trivially carry over. For example, `etcd/raft`
requires that a new replica being added must know the exact state of the cluster
at the moment it is added. Similarly, replicas who are not yet aware of a recent
reconfigurations are not able to receive commands from the new nodes: this means
that a new node serving as a leader cannot help those replicas to catch up.
Nodes not in the cluster cannot catch up with the cluster before being added --
and adding them would reduce availability.

I am not aware of any way to achieve optimal-availability replication in this
model ("optimal" is in with respect to CAP theorem: replicas in configuration
c make progress if a majority of c is available).

As a compromise, I propose mirroring `etcd`-s strategy even though its
availability properties are suboptimal. Later (possibly after
"dissertation"-style configuration change have been formally verified), we may
choose to use that instead. The compromise should have no more issues than
`etcd`.

An `etcd`-style reconfiguration protocol for a keyserver cluster would go as
follows (first see
<https://github.com/coreos/etcd/blob/master/Documentation/runtime-configuration.md>):

1. Important invariants:
	1. Reconfigurations only happen during epoch delimiters; each epoch
	delimiter is potentially a configuration change.
	2. Every epoch is signed by the configuration as of *right after* its epoch
	delimiter. The public keys of the new replicas will be included in that
	epoch (in the form of an `AuthorizationPolicy`).
	3. Each individual replicas only signs epochs according to what it has been
	told directly, ignoring raft state. However, an epoch is published when
	a simple majority of its configuration has signed it, allowing for lagging
	replicas to catch up without blocking signing of epochs.
	4. An epoch delimiter will include a configuration change only if at least
	a simple majority of the previous configuration has indicated that they
	would sign epochs under the new configuration. This *approval* of a new
	configuration is signaled using a special log entry. If an epoch delimiter
	is proposed before the approvals are applied, it is handled as it was
	committed (without a configuration change), and the next epoch delimiter is
	proposed with the configuration change.
2. Operations flow for adding a replica
	1. Inform at least a majority of the existing replicas of the new replica. Wait until
	this majority has performed a configuration change.
	2. Seed the new replica with the exact configuration after step 1 as its
	initial Raftlog configuration, but keep let it have the true initial
	replicas for the Keyserver.
	3. Start the new replica.
	4. Wait for the new replica to catch up (after this, the RaftLog
	replicas must be the same as the Keyserver replicas).
	5. Now it is safe to start a new configuration change.
3. Relevant RPC-s each replica implements and that are called from 2.1 (similar to <https://github.com/coreos/etcd/blob/master/etcdserver/etcdhttp/client.go#L220> `membersHandler` case for `POST`):
	1. `AddReplica`
	2. `RemoveReplica`
4. Relevant log messages:
	1. EpochDelimiter: includes a configuration change (usually a NOP)
	2. ApproveConfigurationChange indicates that a single replica would accept a new configuration.
5. Replica-local state:
	1. map[replica]\*ApproveConfigurationChange -- the single (latest)
	configuration change that each replica has endorsed on the log.
	2. bool -- approveCurrentConfiguration: set to true when transitioning into
	the configuration that the current replica approves of, or when told to move
	into that configuration (2.1) after some other majority has already accepted
	it.

The code that implements a similar flow (as seen by by the members of the
existing cluster) in `etcd` can be found in the following files:
1. <https://github.com/coreos/etcd/blob/f38778160d7d68c65171509e4eb52ced31dbb3af/etcdserver/server.go#L596> `AddMember` (this is ends up being called when `etcdctl` issues an add).
2. <https://github.com/coreos/etcd/blob/f38778160d7d68c65171509e4eb52ced31dbb3af/etcdserver/server.go#L841> `ApplyConfChange` gets called when that add has been committed to the log.
3. <https://github.com/coreos/etcd/blob/f38778160d7d68c65171509e4eb52ced31dbb3af/etcdserver/server.go#L596> `configure` (called from `AddMember`) makes sure to wait with returning to `etcdctl` until the add has been committed and applied.

The code that implements a similar flow (as seen by a new replica being added)
in `etcd` can be found in the following files:
1. <https://github.com/coreos/etcd/blob/master/etcdserver/server.go#L197> `NewServer` case for `!cfg.NewCluster`.
2. <https://github.com/coreos/etcd/blob/df83af944bf2c7503a168abb979a2590f7861977/etcdserver/cluster.go#L414> `ValidateClusterAndAssignIDs`.
3. <https://github.com/coreos/etcd/blob/c530385d6dca7e3625651cca341f7b229f1dfea8/etcdserver/raft.go#L241> `startNode`

This is far very far from an ideal scenario, but I would like to stress that
there are two very different kinds of awkwardness here. Having each replica only
sign what it is told directly is a security property, and maintaining it
requires a round of approval votes before switching to a new configuration.
However, needing to provide each new replica with the exact cluster state as of
when it was added (and risking outage otherwise) is an `etcd/raft` limitation.
Using "dissertation" raft, one could simply have a replica catch up first and
then issue the approvals, after which it would atomically be made a voting
replica.

All of this looks fragile enough that I wouldn't risk having something automatic
manage this cluster...
