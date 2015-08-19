// Copyright 2014-2015 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package server

type broadcastMessage struct {
	channelID uint64
	value     interface{}
}

type subscription struct {
	channelID uint64
	channel   chan interface{}
}

type Broadcaster struct {
	messages    chan broadcastMessage
	subscribers map[uint64]map[chan interface{}]struct{}

	subscribe   chan subscription
	unsubscribe chan subscription
	stop        chan struct{}
}

func NewBroadcaster() *Broadcaster {
	b := &Broadcaster{
		messages:    make(chan broadcastMessage),
		subscribers: make(map[uint64]map[chan interface{}]struct{}),
		subscribe:   make(chan subscription),
		unsubscribe: make(chan subscription),
		stop:        make(chan struct{}),
	}
	go b.run()
	return b
}

func (b *Broadcaster) run() {
	defer close(b.messages)
	defer close(b.subscribe)
	defer close(b.unsubscribe)
	for {
		select {
		case m := <-b.messages:
			if subs, ok := b.subscribers[m.channelID]; ok {
				for ch := range subs {
					ch <- m.value
				}
			}
		case s := <-b.subscribe:
			if _, ok := b.subscribers[s.channelID]; !ok {
				b.subscribers[s.channelID] = make(map[chan interface{}]struct{})
			}
			b.subscribers[s.channelID][s.channel] = struct{}{}
		case s := <-b.unsubscribe:
			delete(b.subscribers[s.channelID], s.channel)
			if len(b.subscribers[s.channelID]) == 0 {
				delete(b.subscribers, s.channelID)
			}
			close(s.channel)
		case <-b.stop:
			for _, subs := range b.subscribers {
				for ch := range subs {
					close(ch)
				}
			}
			return
		}
	}
}

func (b *Broadcaster) Publish(channelID uint64, value interface{}) {
	b.messages <- broadcastMessage{channelID, value}
}

// Starts listening with the channel, which is guaranteed to receive all values
// published after the Subscribe() call.
func (b *Broadcaster) Subscribe(channelID uint64, ch chan interface{}) {
	b.subscribe <- subscription{channelID, ch}
}

// Stops listening with the channel. At some point after the Unsubscribe() call
// begins, the channel will stop receiving values and be closed. Subscribers
// are guaranteed to receive all values published before the Unsubscribe() call.
func (b *Broadcaster) Unsubscribe(channelID uint64, ch chan interface{}) {
	b.unsubscribe <- subscription{channelID, ch}
}

// No calls may be made on the broadcaster after Stop() is initiated.
func (b *Broadcaster) Stop() {
	close(b.stop)
}
