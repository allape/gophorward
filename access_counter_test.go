package gophorward

import (
	"log"
	"testing"
	"time"
)

func TestAccessCounter(t *testing.T) {
	ac := NewAccessCounter(2 * time.Second)

	for i := 0; i < 60; i++ {
		ok := ac.CanAccess("abc", 60)

		if !ok {
			t.Fatalf("Expect %v got %v", true, ok)
		}
	}

	for i := 0; i < 60; i++ {
		ok := ac.CanAccess("abc", 60)

		if ok {
			t.Fatalf("Expect %v got %v", false, ok)
		}
	}

	doubleTime := ac.TimeUnit * 2
	log.Printf("wait for %s to skip time window", doubleTime.String())
	time.Sleep(doubleTime)
	log.Printf("%s later", doubleTime.String())

	for i := 0; i < 60; i++ {
		ok := ac.CanAccess("abc", 60)

		if !ok {
			t.Fatalf("Expect %v got %v", true, ok)
		}
	}

	for i := 0; i < 60; i++ {
		ok := ac.CanAccess("abc", 60)

		if ok {
			t.Fatalf("Expect %v got %v", false, ok)
		}
	}
}

func TestNow(t *testing.T) {
	ac := NewAccessCounter(time.Second) // time unit less than second may create a small time window which will make this test fail

	secsSince1970 := uint64(time.Now().UnixMilli() / 1000)
	if secsSince1970 != ac.now() {
		t.Fatalf("Expect %v got %v", secsSince1970, ac.now())
	}

	ac.TimeUnit = time.Minute
	minsSince1970 := uint64(time.Now().UnixMilli() / 1000 / 60)
	if minsSince1970 != ac.now() {
		t.Fatalf("Expect %v got %v", minsSince1970, ac.now())
	}

	ac.TimeUnit = time.Hour
	hoursSince1970 := uint64(time.Now().UnixMilli() / 1000 / 60 / 60)
	if hoursSince1970 != ac.now() {
		t.Fatalf("Expect %v got %v", hoursSince1970, ac.now())
	}
}
