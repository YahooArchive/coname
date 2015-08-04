package kvlog

import "github.com/yahoo/coname/server/replication"

func entrySize(le replication.LogEntry) int {
	return len(le.Data) + len(le.Reconfiguration)
}

func marshalEntry(le replication.LogEntry) []byte {
	if le.Data != nil {
		return append([]byte{0}, le.Data...)
	}
	return append([]byte{1}, le.Reconfiguration...)
}

func unmarshalEntry(le *replication.LogEntry, b []byte) {
	*le = replication.LogEntry{}
	if len(b) == 0 {
		return
	}
	if b[0] == 0 {
		le.Data = append([]byte{}, b[1:]...)
	}
	if b[0] == 1 {
		le.Reconfiguration = append([]byte{}, b[1:]...)
	}
}
