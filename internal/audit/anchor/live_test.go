package anchor_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/anchor"
)

func TestRekorPublicInstanceRoundTrip(t *testing.T) {
	url, trustPath := os.Getenv("TOLLKEEPER_TEST_REKOR_URL"), os.Getenv("TOLLKEEPER_TEST_REKOR_TRUST")
	if url == "" || trustPath == "" {
		t.Skip(
			"TOLLKEEPER_TEST_REKOR_URL and TOLLKEEPER_TEST_REKOR_TRUST not set; this test writes a public, permanent entry",
		)
	}
	trust, err := anchor.LoadTrust([]string{trustPath}, "")
	if err != nil {
		t.Fatal(err)
	}
	if vkeys := os.Getenv("TOLLKEEPER_TEST_REKOR_WITNESSES"); vkeys != "" {
		trust, err = trust.WithWitnesses(strings.Split(vkeys, ","), 1)
		if err != nil {
			t.Fatal(err)
		}
	}
	c, err := anchor.NewClient(url, "tollkeeper-integration-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	k := key(t)
	r := audit.CheckpointRef{ChainID: "tollkeeper-integration-test", Seq: 1, Hash: audit.HashBytes([]byte(t.Name()))}
	sub, err := anchor.Sign(k, r)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := c.Submit(t.Context(), sub)
	if err != nil {
		t.Fatal(err)
	}
	origin, _, _ := strings.Cut(rec.Checkpoint, "\n")
	a := anchor.NewAnchor(r, pubOf(t, k), origin, rec)
	ev, err := anchor.NewReceiptVerifier(trust).VerifyAnchor(r.ChainID, a, r, pubOf(t, k))
	if err != nil {
		t.Fatalf("receipt from %s does not verify: %v", url, err)
	}
	t.Logf("anchored at %s#%d in a tree of %d, %d witnesses, witnessed at %s",
		ev.Log, ev.LogIndex, ev.TreeSize, ev.Witnesses, ev.WitnessedAt)
}

func TestSigstoreTimestampAuthorityRoundTrip(t *testing.T) {
	url := os.Getenv("TOLLKEEPER_TEST_TSA_URL")
	if url == "" {
		t.Skip("TOLLKEEPER_TEST_TSA_URL not set")
	}
	trust, err := anchor.LoadTrust([]string{"testdata/trusted_root.json"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !trust.HasTimestampAuthority() {
		t.Fatal("trusted root has no timestamp authority")
	}
	tc, err := anchor.NewTimestampClient(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := audit.CheckpointRef{ChainID: "tollkeeper-integration-test", Seq: 1, Hash: audit.HashBytes([]byte(t.Name()))}
	statement, err := audit.AnchorStatement(r.ChainID, r.Seq, r.Hash)
	if err != nil {
		t.Fatal(err)
	}
	token, err := tc.Timestamp(t.Context(), statement)
	if err != nil {
		t.Fatal(err)
	}
	at, err := anchor.VerifyTimestampToken(trust, token, r)
	if err != nil {
		t.Fatalf("token from %s does not verify against the trusted root: %v", url, err)
	}
	t.Logf("timestamped at %s", at)
}
