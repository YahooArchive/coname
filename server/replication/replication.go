package replication

import (
	"github.com/yahoo/coname/internal/golang.org/x/net/context"
)

// LogReplicator is a generic interface to state-machine replication logs.  The
// log is a mapping from uint64 slot indices to []byte entries in which all
// entries that have been committed are reliably persistent even throughout
// machine crashes and data losses at a limited number of replicas. This is
// achieved by trading off availability: proposing a new netry does not
// necessarily mean it will be committed. One would use this interface
// similarly to a local write-ahead log, except that this interface does not
// support log compaction (it is intended for use when the entire log needs to
// be kept around anyway).
// Start(lo) must be called exactly once before any other method is called, and
// no methods must be called after Close is called. The other three methods may
// be called concurrently.
type LogReplicator interface {
	// Start sets an internal field lo; later WaitCommitted will return entries
	// with indices >= lo. Start must be called before any other methods are.
	Start(lo uint64) error

	// Propose moves to append data to the log. It is not guaranteed that the
	// entry will get appended, though, due to node or network failures.
	// data : []*mut // ownership of the slice contents is transferred to LogReplicator
	Propose(ctx context.Context, data []byte)

	// GetCommitted loads committed entries for post-replication distribution:
	// All returned entries are consecutive and start at Index=lo, but do not
	// necessarily go all the way up to (but not including) Index=hi. At least
	// one entry is returned as long as there is one in the specified range. If
	// possible, no more than maxSize bytes are returned.
	// ret: []&[]byte // All returned byte slices are read-only for the caller.
	GetCommitted(lo, hi, maxSize uint64) ([][]byte, error)

	// WaitCommitted returns a channel that returns new committed entries,
	// starting with the index passed to Start.
	// All calls return the same channel.
	// ch : chan (&[]byte) // all read values are read-only to the caller
	WaitCommitted() <-chan []byte

	// Close cleanly stops logging requests. No calls to Propose or
	// GetCommitted must be started after Close has been called (and the values
	// handed to ongoing Propose calls may not get committed). WaitCommitted
	// channel is closed.
	Close() error
}
