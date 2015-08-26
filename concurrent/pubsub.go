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

package concurrent

// PublishSubscribe implements the publish-subscribe pattern where messages have
// uint64 "tags" (which could be thought of as "channels"). At any time,
// messages can be published with Publish, and subscriptions to messages with a
// particular tag can be created and stopped with Subscribe and Unsubscribe.
// PublishSubscribe is somewhat asynchronous: Publish calls do not wait for the
// value to be sent to subscribers. However, if a send to a subscribed channel
// blocks, the entire state machine blocks; thus, subscribers should either
// buffer or guarantee quick processing. Because of this, PublishSubscribe can
// guarantee that subscriptions will receive all values published after the
// Subscribe call and before the Unsubscribe call (with "after" and "before"
// defined according to Go's memory model [https://golang.org/ref/mem]).
type PublishSubscribe struct {
	messages    chan broadcastMessage
	subscribers map[uint64]map[chan<- interface{}]struct{}

	subscribe   chan subscription
	unsubscribe chan subscription
	stop        chan struct{}
}

type broadcastMessage struct {
	tag   uint64
	value interface{}
}

type subscription struct {
	tag     uint64
	channel chan<- interface{}
}

func NewPublishSubscribe() *PublishSubscribe {
	p := &PublishSubscribe{
		messages:    make(chan broadcastMessage),
		subscribers: make(map[uint64]map[chan<- interface{}]struct{}),
		subscribe:   make(chan subscription),
		unsubscribe: make(chan subscription),
		stop:        make(chan struct{}),
	}
	go p.run()
	return p
}

func (p *PublishSubscribe) run() {
	defer close(p.messages)
	defer close(p.subscribe)
	defer close(p.unsubscribe)
	for {
		select {
		case m := <-p.messages:
			if subs, ok := p.subscribers[m.tag]; ok {
				for ch := range subs {
					ch <- m.value
				}
			}
		case s := <-p.subscribe:
			if _, ok := p.subscribers[s.tag]; !ok {
				p.subscribers[s.tag] = make(map[chan<- interface{}]struct{})
			}
			p.subscribers[s.tag][s.channel] = struct{}{}
		case s := <-p.unsubscribe:
			delete(p.subscribers[s.tag], s.channel)
			if len(p.subscribers[s.tag]) == 0 {
				delete(p.subscribers, s.tag)
			}
			close(s.channel)
		case <-p.stop:
			for _, subs := range p.subscribers {
				for ch := range subs {
					close(ch)
				}
			}
			return
		}
	}
}

func (p *PublishSubscribe) Publish(tag uint64, value interface{}) {
	p.messages <- broadcastMessage{tag, value}
}

// Starts listening with the channel, which is guaranteed to receive all values
// published with that tag after the Subscribe() call.
func (p *PublishSubscribe) Subscribe(tag uint64, ch chan<- interface{}) {
	p.subscribe <- subscription{tag, ch}
}

// Stops listening with the channel. At some point after the Unsubscribe() call
// begins, the channel will stop receiving values and be closed. Subscribers
// are guaranteed to receive all values published with that tag before the
// Unsubscribe() call.
func (p *PublishSubscribe) Unsubscribe(tag uint64, ch chan<- interface{}) {
	p.unsubscribe <- subscription{tag, ch}
}

// No calls may be made on the broadcaster after Stop() is initiated.
func (p *PublishSubscribe) Stop() {
	close(p.stop)
}
