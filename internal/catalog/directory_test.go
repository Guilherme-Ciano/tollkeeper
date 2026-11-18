package catalog

import (
	"errors"
	"testing"
)

func TestDirectoryRoutesByURIAndTemplate(t *testing.T) {
	t.Parallel()
	d := NewDirectory(10)
	changed, rejected, err := d.Replace("files", []Entry{
		{Kind: KindResource, Name: "file:///readme.md"},
		{Kind: KindTemplate, Name: "file:///docs/{name}"},
		{Kind: KindPrompt, Name: "files__summarize", Original: "summarize"},
	})
	if err != nil || !changed || len(rejected) != 0 {
		t.Fatalf("replace: %v %v %v", changed, rejected, err)
	}
	if _, _, err := d.Replace("notes", []Entry{
		{Kind: KindResource, Name: "file:///readme.md"},
		{Kind: KindResource, Name: "notes://today"},
	}); err != nil {
		t.Fatal(err)
	}
	snap := d.Snapshot()
	if e, ok := snap.Resource("file:///readme.md"); !ok || e.Upstream != "files" {
		t.Fatalf("collision did not keep the first owner: %+v", e)
	}
	if e, ok := snap.Resource("file:///docs/intro"); !ok || e.Kind != KindTemplate || e.Upstream != "files" {
		t.Fatalf("template routing: %+v %t", e, ok)
	}
	if _, ok := snap.Resource("file:///other/intro"); ok {
		t.Fatal("unmatched uri routed")
	}
	if e, ok := snap.Lookup(KindPrompt, "files__summarize"); !ok || e.Original != "summarize" {
		t.Fatalf("prompt lookup: %+v", e)
	}
	if changed, _, err := d.Replace("notes", []Entry{
		{Kind: KindResource, Name: "file:///readme.md"},
		{Kind: KindResource, Name: "notes://today"},
	}); err != nil || changed {
		t.Fatalf("identical replace: changed=%t err=%v", changed, err)
	}
	if _, _, err := d.Replace("files", nil); err != nil {
		t.Fatal(err)
	}
	if e, ok := d.Snapshot().Resource("file:///readme.md"); ok {
		t.Fatalf("removed upstream still routes: %+v", e)
	}
}

func TestDirectoryRejectsBadEntries(t *testing.T) {
	t.Parallel()
	d := NewDirectory(2)
	_, rejected, err := d.Replace("u", []Entry{
		{Kind: KindTemplate, Name: "file:///{unclosed"},
		{Kind: KindResource, Name: "bad\nuri"},
		{Kind: "tool", Name: "x"},
		{Kind: KindPrompt, Name: ""},
	})
	if err != nil || len(rejected) != 4 {
		t.Fatalf("rejected %d (%v), err %v", len(rejected), rejected, err)
	}
	_, _, err = d.Replace("u", []Entry{
		{Kind: KindResource, Name: "a://1"}, {Kind: KindResource, Name: "a://2"}, {Kind: KindResource, Name: "a://3"},
	})
	if !errors.Is(err, ErrMaxEntries) {
		t.Fatalf("limit: %v", err)
	}
}
