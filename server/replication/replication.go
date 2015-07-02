package replication

import (
	"github.com/yahoo/coname/internal/golang.org/x/net/context"
)

// ReplicatedLog is a generic interface to state-machine replication logs.
// The log is a mapping from uint64 slot indices to []byte entries.  Start(lo)
// must be called exactly once before any other method is called. The other
// three methods may be called concurrently. This interface here does not
// support log compaction.
type ReplicatedLog interface {
	// Start sets an internal field lo; later WaitCommitted will return entries
	// with indices >= lo.
	Start(lo uint64) error

	// Propose moves to append data to the log. It is not guaranteed that the
	// entry will get appended, though, due to node or network failures
	// data : *mut // ownership is transferred to ReplicatedLog
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
	// ch : chan (*mut Entry) // reader owns read values
	WaitCommitted() <-chan []byte

	// Close cleanly stops logging requests. No calls to Propose or
	// GetCommitted must be started after Close has been called (and the values
	// handed to ongoing Propose calls may not get committed). WaitCommitted
	// channel is closed.
	Close() error
}
