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

import (
	"testing"
)

func TestPublishWithoutSubscribers(t *testing.T) {
	b := NewPublishSubscribe()
	defer b.Stop()
	b.Publish(0, "hello")
}

func TestPublishOnDifferentChannel(t *testing.T) {
	b := NewPublishSubscribe()
	ch := make(chan interface{})
	b.Subscribe(1, ch)
	b.Publish(2, "hi")
	b.Stop()
	if _, ok := <-ch; ok {
		t.Fatal("Got a value on the wrong channel")
	}
}

func TestPublishOnSameChannel(t *testing.T) {
	b := NewPublishSubscribe()
	ch := make(chan interface{})
	b.Subscribe(1, ch)
	values := []interface{}{"hey", 3, "sup"}
	go func() {
		for _, v := range values {
			b.Publish(1, v)
		}
		b.Unsubscribe(1, ch)
	}()
	for _, want := range values {
		if v, ok := <-ch; !ok || v != want {
			if !ok {
				t.Fatal("Didn't get a value")
			} else {
				t.Fatalf("Wrong value: wanted %s, got %s", want, v)
			}
		}
	}
	if _, ok := <-ch; ok {
		t.Fatal("Channel didn't close")
	}
	b.Stop()
}

func TestPublishToMultipleSubscribers(t *testing.T) {
	const nSubs = 3
	b := NewPublishSubscribe()
	chs := []chan interface{}{}
	values := []interface{}{"hey", 3, "sup"}
	for i := 0; i < nSubs; i++ {
		ch := make(chan interface{}, len(values))
		b.Subscribe(1, ch)
		chs = append(chs, ch)
	}
	for _, v := range values {
		b.Publish(1, v)
	}
	for _, ch := range chs {
		b.Unsubscribe(1, ch)
	}
	for _, ch := range chs {
		for _, want := range values {
			if v, ok := <-ch; !ok || v != want {
				if !ok {
					t.Fatal("Didn't get a value")
				} else {
					t.Fatalf("Wrong value: wanted %s, got %s", want, v)
				}
			}
		}
		if _, ok := <-ch; ok {
			t.Fatal("Channel didn't close")
		}
	}
	b.Stop()
}
