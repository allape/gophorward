package gophorward

import (
	"sync"
	"time"
)

type AccessCounterKey string

type AccessCounterItem struct {
	timeWindow uint64
	Count      uint64 // *atomic.Uint64
}

type AccessCounter struct {
	TimeUnit time.Duration

	items  map[AccessCounterKey]*AccessCounterItem
	locker sync.Mutex
}

func (ac *AccessCounter) now() uint64 {
	return uint64(time.Now().UnixNano() / int64(ac.TimeUnit))
}

func (ac *AccessCounter) CleanUp() {
	ac.locker.Lock()
	defer ac.locker.Unlock()

	now := ac.now()
	for s, counter := range ac.items {
		if counter.timeWindow < now {
			delete(ac.items, s)
		}
	}
}

func (ac *AccessCounter) CanAccess(key AccessCounterKey, maxCount uint64) bool {
	ac.locker.Lock()
	defer ac.locker.Unlock()

	now := ac.now()

	counter, ok := ac.items[key]
	if !ok || counter.timeWindow < now {
		counter = &AccessCounterItem{
			timeWindow: now,
			Count:      0,
		}
		ac.items[key] = counter
	}

	counter.Count += 1 // overflow?

	return counter.Count <= maxCount
}

func NewAccessCounter(timeUnit time.Duration) *AccessCounter {
	return &AccessCounter{
		TimeUnit: timeUnit,

		items: make(map[AccessCounterKey]*AccessCounterItem),
	}
}
