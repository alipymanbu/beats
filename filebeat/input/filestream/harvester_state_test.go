// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package filestream

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	loginp "github.com/elastic/beats/v7/filebeat/input/filestream/internal/input-logfile"
	"github.com/elastic/beats/v7/libbeat/common/file"
)

func completeDesc(sum string) loginp.FileDescriptor {
	return loginp.FileDescriptor{Fingerprint: completeFP(sum)}
}

func growingDesc(raw string) loginp.FileDescriptor {
	return loginp.FileDescriptor{Fingerprint: loginp.FingerprintID{Raw: raw}}
}

// tempFileInfo returns the stat of a fresh temp file. Distinct calls yield
// distinct OS identities on every platform.
func tempFileInfo(t *testing.T) file.ExtendedFileInfo {
	t.Helper()
	fi, err := os.Stat(writeTempFile(t, "x"))
	require.NoError(t, err, "stat temp file")
	return file.ExtendFileInfo(fi)
}

// nonZeroOSState returns the non-zero StateOS of a fresh temp file.
func nonZeroOSState(t *testing.T) file.StateOS {
	t.Helper()
	st := tempFileInfo(t).GetOSState()
	require.NotEqual(t, file.StateOS{}, st, "stat must produce a non-zero StateOS")
	return st
}

func TestFileStateTable_RegisterPinLookup(t *testing.T) {
	tbl := newFileStateTable()

	// No entry yet.
	_, ok := tbl.LookupOSState("id-1")
	assert.False(t, ok, "LookupOSState must fail before any Register")

	h := tbl.Register("id-1", completeDesc("sum-1"))
	assert.NotNil(t, h, "Register must return a handle")

	// Registered but not pinned: no OS state yet.
	_, ok = tbl.LookupOSState("id-1")
	assert.False(t, ok, "LookupOSState must fail on an unpinned entry")

	assert.Equal(t, "sum-1", h.FingerprintSum(),
		"FingerprintSum must return the completed Sum passed to Register")

	want := nonZeroOSState(t)
	h.PinOSState(want)
	got, ok := tbl.LookupOSState("id-1")
	assert.True(t, ok, "LookupOSState must succeed on a pinned, non-zero entry")
	assert.Equal(t, want, got, "LookupOSState must return the pinned StateOS")
}

func TestFileStateTable_LookupZeroStateOSReadsAsNoPin(t *testing.T) {
	tbl := newFileStateTable()
	h := tbl.Register("id-1", completeDesc("sum-1"))

	// A zero StateOS (e.g. Windows loadFileId failing) must read as "no pin".
	h.PinOSState(file.StateOS{})
	_, ok := tbl.LookupOSState("id-1")
	assert.False(t, ok, "a zero pinned StateOS must read as no pin")
}

func TestFileStateTable_FingerprintSum(t *testing.T) {
	tbl := newFileStateTable()

	complete := tbl.Register("complete", completeDesc("the-sum"))
	assert.Equal(t, "the-sum", complete.FingerprintSum(),
		"a completed fingerprint must expose its Sum")

	growing := tbl.Register("growing", growingDesc("deadbeef"))
	assert.Empty(t, growing.FingerprintSum(),
		"an incomplete fingerprint must expose no Sum")
}

func TestFileStateTable_UpdateDescriptorUpdatesIfPresent(t *testing.T) {
	tbl := newFileStateTable()

	tbl.UpdateDescriptor("absent", completeDesc("sum"))
	_, ok := tbl.LookupOSState("absent")
	assert.False(t, ok, "UpdateDescriptor must not insert an entry for an absent key")

	h := tbl.Register("id-1", growingDesc("deadbeef"))
	assert.Empty(t, h.FingerprintSum(), "handle must start below threshold with no Sum")

	tbl.UpdateDescriptor("id-1", completeDesc("final-sum"))
	assert.Equal(t, "final-sum", h.FingerprintSum(),
		"UpdateDescriptor must make the completed Sum visible on the handle")
}

func TestFileStateTable_RekeyPreservesHandle(t *testing.T) {
	tbl := newFileStateTable()
	h := tbl.Register("old-id", completeDesc("sum-1"))
	pinned := nonZeroOSState(t)
	h.PinOSState(pinned)

	h.Rekey("new-id")

	_, ok := tbl.LookupOSState("old-id")
	assert.False(t, ok, "old key must no longer resolve after Rekey")

	got, ok := tbl.LookupOSState("new-id")
	assert.True(t, ok, "new key must resolve to the migrated handle after Rekey")
	assert.Equal(t, pinned, got, "Rekey must preserve the pinned StateOS")
	assert.Equal(t, "sum-1", h.FingerprintSum(), "Rekey must preserve the handle's descriptor")

	tbl.UpdateDescriptor("new-id", completeDesc("sum-2"))
	assert.Equal(t, "sum-2", h.FingerprintSum(),
		"UpdateDescriptor under the new key must reach the migrated handle")
	tbl.UpdateDescriptor("old-id", completeDesc("ignored"))
	assert.Equal(t, "sum-2", h.FingerprintSum(),
		"UpdateDescriptor under the stale old key must not reach the handle")
}

func TestFileStateTable_RekeyDeregisteredIsNoOp(t *testing.T) {
	tbl := newFileStateTable()
	h := tbl.Register("old-id", completeDesc("sum"))
	h.PinOSState(nonZeroOSState(t))
	tbl.Deregister(h)

	h.Rekey("new-id")
	_, ok := tbl.LookupOSState("new-id")
	assert.False(t, ok, "Rekey of a deregistered handle must not create an entry")
}

func TestFileStateTable_DeregisterCompareAndDelete(t *testing.T) {
	t.Run("removes its own entry", func(t *testing.T) {
		tbl := newFileStateTable()
		h := tbl.Register("id-1", completeDesc("sum"))
		h.PinOSState(nonZeroOSState(t))

		tbl.Deregister(h)
		_, ok := tbl.LookupOSState("id-1")
		assert.False(t, ok, "Deregister must remove the handle's own entry")
	})

	t.Run("displaced handle Deregister no-ops under Restart overlap", func(t *testing.T) {
		tbl := newFileStateTable()

		// During a restart, the new harvester can register before the old one closes.
		old := tbl.Register("id-1", completeDesc("old"))
		newer := tbl.Register("id-1", completeDesc("new"))
		newerPin := nonZeroOSState(t)
		newer.PinOSState(newerPin)

		// Removing the old handle must preserve the newer entry.
		tbl.Deregister(old)
		got, ok := tbl.LookupOSState("id-1")
		assert.True(t, ok, "the newer handle must survive the displaced handle's Deregister")
		assert.Equal(t, newerPin, got, "the surviving entry must be the newer handle's")

		// The newer handle can still deregister itself.
		tbl.Deregister(newer)
		_, ok = tbl.LookupOSState("id-1")
		assert.False(t, ok, "the newer handle must be able to deregister itself")
	})

	t.Run("Deregister after Rekey removes at the current key", func(t *testing.T) {
		tbl := newFileStateTable()
		h := tbl.Register("old-id", completeDesc("sum"))
		h.PinOSState(nonZeroOSState(t))
		h.Rekey("new-id")

		tbl.Deregister(h)
		_, ok := tbl.LookupOSState("new-id")
		assert.False(t, ok, "Deregister must remove the handle at its post-Rekey key")
	})
}

func TestFileStateTable_NilSafety(t *testing.T) {
	var tbl *fileStateTable
	var h *openFileState

	// None of these must panic on a nil table / nil handle.
	assert.Nil(t, tbl.Register("id", completeDesc("sum")),
		"Register on a nil table must return nil")
	tbl.UpdateDescriptor("id", completeDesc("sum"))
	h.Rekey("b")
	tbl.Deregister(h)
	_, ok := tbl.LookupOSState("id")
	assert.False(t, ok, "LookupOSState on a nil table must report no pin")

	h.PinOSState(nonZeroOSState(t))
	assert.Empty(t, h.FingerprintSum(), "FingerprintSum on a nil handle must be empty")

	// A handle obtained from a real table must tolerate a nil-table Deregister path too.
	realTable := newFileStateTable()
	realHandle := realTable.Register("id", completeDesc("sum"))
	tbl.Deregister(realHandle) // nil table, real handle: still a no-op, no panic
}

func TestFileStateTable_PinnedDescriptor(t *testing.T) {
	tbl := newFileStateTable()
	pin := nonZeroOSState(t)
	descAt := func(path, sum string) loginp.FileDescriptor {
		return loginp.FileDescriptor{Filename: path, Fingerprint: completeFP(sum)}
	}

	_, _, ok := tbl.PinnedDescriptor("/logs/a.log")
	assert.False(t, ok, "PinnedDescriptor must fail before any Register")

	h := tbl.Register("id-1", descAt("/logs/a.log", "sum-1"))
	_, _, ok = tbl.PinnedDescriptor("/logs/a.log")
	assert.False(t, ok, "PinnedDescriptor must fail before PinOSState")

	// A zero StateOS is not a usable identity: still no candidate.
	h.PinOSState(file.StateOS{})
	_, _, ok = tbl.PinnedDescriptor("/logs/a.log")
	assert.False(t, ok, "a zero pin must not make the handle a candidate")

	h.PinOSState(pin)
	got, gotPin, ok := tbl.PinnedDescriptor("/logs/a.log")
	assert.True(t, ok, "PinnedDescriptor must resolve the pinned handle at its path")
	assert.Equal(t, "sum-1", got.Fingerprint.Sum, "PinnedDescriptor must return the handle's descriptor")
	assert.Equal(t, pin, gotPin, "PinnedDescriptor must return the handle's pin")

	// The scanner reports the file at a new path (rename): the index follows.
	tbl.UpdateDescriptor("id-1", descAt("/logs/b.log", "sum-1"))
	_, _, ok = tbl.PinnedDescriptor("/logs/a.log")
	assert.False(t, ok, "the old path must no longer resolve after the descriptor moved")
	got, _, ok = tbl.PinnedDescriptor("/logs/b.log")
	assert.True(t, ok, "the new path must resolve after the descriptor moved")
	assert.Equal(t, "sum-1", got.Fingerprint.Sum, "the moved entry must keep its descriptor")

	tbl.Deregister(h)
	_, _, ok = tbl.PinnedDescriptor("/logs/b.log")
	assert.False(t, ok, "PinnedDescriptor must fail after Deregister clears the index")
}

func TestFileStateTable_PinnedDescriptorDisplacedHandle(t *testing.T) {
	tbl := newFileStateTable()
	desc := loginp.FileDescriptor{Filename: "/logs/a.log", Fingerprint: completeFP("old")}

	// A replacement harvester takes ownership of both indexes before the old
	// harvester closes.
	old := tbl.Register("id-old", desc)
	old.PinOSState(nonZeroOSState(t))
	desc.Fingerprint = completeFP("new")
	newer := tbl.Register("id-new", desc)
	newer.PinOSState(nonZeroOSState(t))

	tbl.Deregister(old)
	got, _, ok := tbl.PinnedDescriptor("/logs/a.log")
	assert.True(t, ok, "the newer handle must keep the path index after the displaced one deregisters")
	assert.Equal(t, "new", got.Fingerprint.Sum, "the surviving index entry must be the newer handle's")

	tbl.Deregister(newer)
	_, _, ok = tbl.PinnedDescriptor("/logs/a.log")
	assert.False(t, ok, "the newer handle's Deregister must clear the path index")
}

// TestFileStateTable_ConcurrentAccess runs readers and writers concurrently.
func TestFileStateTable_ConcurrentAccess(t *testing.T) {
	tbl := newFileStateTable()
	pinned := nonZeroOSState(t)

	const workers = 16
	const ops = 200
	var wg sync.WaitGroup

	for i := range workers {
		key := "id-" + strconv.Itoa(i)
		var current atomic.Pointer[openFileState]

		wg.Go(func() {
			for range ops {
				h := tbl.Register(key, loginp.FileDescriptor{Filename: "/logs/" + key, Fingerprint: loginp.FingerprintID{Raw: "dead"}})
				current.Store(h)
				h.PinOSState(pinned)
				_ = h.FingerprintSum()
				tbl.Deregister(h)
			}
		})

		wg.Go(func() {
			for range ops {
				tbl.UpdateDescriptor(key, loginp.FileDescriptor{Filename: "/logs/" + key + ".1", Fingerprint: completeFP("sum")})
				_, _ = tbl.LookupOSState(key)
				_, _, _ = tbl.PinnedDescriptor("/logs/" + key)
				_, _, _ = tbl.PinnedDescriptor("/logs/" + key + ".1")
			}
		})

		wg.Go(func() {
			for range ops {
				h := current.Load()
				h.Rekey(key + "-moved")
				h.Rekey(key)
			}
		})
	}

	wg.Wait()
}
