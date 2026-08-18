package service

import (
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
)

func TestRecipientSetNeedsCeremony(t *testing.T) {
	tests := []struct {
		name      string
		old, next string
		oldIDs    []int64
		nextIDs   []int64
		want      bool
	}{
		{name: "all to private narrows", old: "all", next: "private"},
		{name: "all to selected narrows", old: "all", next: "selected", nextIDs: []int64{1}},
		{name: "selected removal narrows", old: "selected", next: "selected", oldIDs: []int64{1, 2}, nextIDs: []int64{2}},
		{name: "selected addition widens", old: "selected", next: "selected", oldIDs: []int64{1}, nextIDs: []int64{1, 2}, want: true},
		{name: "private to selected changes class", old: "private", next: "selected", nextIDs: []int64{1}, want: true},
		{name: "selected to private changes class", old: "selected", next: "private", oldIDs: []int64{1}, want: true},
		{name: "private to all widens", old: "private", next: "all", want: true},
		{name: "unchanged selected ordering", old: "selected", next: "selected", oldIDs: []int64{2, 1}, nextIDs: []int64{1, 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := adapter.RecipientSetNeedsCeremony(test.old, test.oldIDs, test.next, test.nextIDs); got != test.want {
				t.Fatalf("RecipientSetNeedsCeremony() = %v, want %v", got, test.want)
			}
		})
	}
}
