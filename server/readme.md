# End-to-End keyserver implementation

The keyserver implementation is structured as a log-driven statemachine to
support linearizable high-availability replication. The log in `replication`
supports two main operations: Propose, which possibly appends an entry, and
`WaitCommitted`, which returns new entries that are appended. All *guarantees* the server
provides are provided through the log: for example, no new epoch is signed
before all information about it has been committed. However, there are also
*nice-to-haves*, for example reducing the load on the log, which are handled by
sometimes holding back calls to `Propose` when it is likely that the appended
value would be ignored anyway.

The lifecycle of an update is as follows:

1. The client calls the update RPC
2. The update is `Propose`-d and appended to the log
3. `run` gets the update from `WaitCommitted`, calls `step` with it. `step`
prepares an atomic change (`kv.Batch`) to the local database, and world-visible
actions to be taken after the state change has been persisted (`deferredIO`).
4. `run` gets an epoch delimiter from the log (how it gets there will be
described later) and calls `step` on it; `step` composes and signs a summary of
the new keyserver state and pushes it into the log (the "epoch head").
5. `run` gets receives the signatures on the new epoch head from a majority of replicas and combines them to form the keyserver signature.
6. The updates and the ratified state summary are made available to verifiers.
7. Verifiers push ratifications, the ratifications get proposed to the log.
8. `run` receives verifier ratifications from `WaitCommitted`, stores them in the local database.

Epoch delimiters are inserted equivalentlry to the following pseudocode:

	for {
		if we are ALL
			likely the the leader of the cluster
			AND at least RetryEpochInterval has passed since the last time we `Propose`d an epoch delimiter
			AND either
				at least MinEpochInterval has passed since last ratification AND a new update has happened since the last delimiter
				at least MaxEpochInteval has passed since the last ratification
			then {
			`Propose` new EpochDelimiter with the next unused seq number and current time
			}
	}

In the implementation, this busy-loop is turned into a non-blocking state
machine by tracking changes to all inputs using channels. This implementation
pattern is known as "sensitivity list" (in Verilog, for example) and is used for
all proposals that need to be retried (most do!).

A key-value database is used for local storage, its key space is split into
tables based on the first byte of the key as specified in `tables.go`.
Big-endian unsigned integers are used to preserve sorting order for range
traversals and cache locality.

The database interface also serves as a testing output  (we really care that
database writes happen before network requests, for example).
