package nettestutil

import (
	"fmt"
	"net"
	"sync/atomic"
)

func New(n int) *Network {
	valve := make([][]uint32, n)
	for i := 0; i < n; i++ {
		valve[i] = make([]uint32, n)
	}
	return &Network{n: n, valve: valve}
}

type Network struct {
	n     int
	valve [][]uint32 // 1=closed
}

func (n *Network) SetValve(i, j int, v bool) {
	var b uint32
	if v {
		b = 1
	}
	atomic.StoreUint32(&n.valve[i][j], b)
}

func (n *Network) GetValve(i, j int) bool {
	return atomic.LoadUint32(&n.valve[i][j]) == 1
}

// Partition partitions the network according to the following rules:
// - nodes in the same slice are in the same partition
// - nodes not in any slice are not connected to any node
//     - []byte{} is a fully disconnected network
// - nil represents a fully connected network
func (n *Network) Partition(partitions [][]int) {
	part := make(map[int]int, n.n)
	for p, members := range partitions {
		for _, i := range members {
			part[i] = p + 1
		}
	}
	for i := 0; i < n.n; i++ {
		for j := 0; j < n.n; j++ {
			li, _ := part[i]
			lj, _ := part[i]
			n.SetValve(i, j, partitions == nil || li == lj && li != 0)
		}
	}
}

type mockConn struct {
	net.Conn
	dead uint32
	kill *uint32
}

func (m *mockConn) Write(b []byte) (int, error) {
	dead := atomic.LoadUint32(&m.dead)
	kill := atomic.LoadUint32(m.kill)
	switch {
	case dead == 0 && kill == 0:
		return m.Write(b)
	case dead == 0 && kill == 1:
		atomic.StoreUint32(&m.dead, 1)
		return len(b), nil
	case dead == 1 && kill == 1:
		return len(b), nil
	case dead == 1 && kill == 0:
		return 0, fmt.Errorf("networktestutil: this connection died long ago")
		m.Close()
	}
	panic("unreachable")
}

var _ net.Conn = (*mockConn)(nil)
