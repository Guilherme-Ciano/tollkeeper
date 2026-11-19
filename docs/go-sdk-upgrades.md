# go-sdk upgrades

tollkeeper pins go-sdk v1.8.0. The [`go-sdk-next`](../.github/workflows/go-sdk-next.yml) workflow builds and tests against the newest go-sdk tag, pre-releases included, every Monday and on demand. It does not gate pull requests; a red run means the next upgrade needs work.

The fast path for `tools/call` ([`internal/gateway/fastpath.go`](../internal/gateway/fastpath.go)) reproduces go-sdk's result rules so that responses and audit records match the SDK path byte for byte. Those rules change between go-sdk versions, and the differential test (`TestFastPathMatchesSDKPath`) is what reports it.

## v1.9.0-pre.1 (checked 2026-11-18)

The module builds, `go vet` is clean, and every package except `internal/gateway` passes. The differential test fails in three ways:

| Change in go-sdk | Effect on tollkeeper | Work for the upgrade |
|---|---|---|
| The result that server middleware sees is serialized differently from v1.8 | The SDK path's audit `result_hash` changes for every result; responses on the wire still match | Hash the same bytes on both paths, ideally the bytes sent to the client, and note the change in the audit format docs |
| An upstream that answers `resultType: "input_required"` with no `inputRequests` keeps that type instead of being corrected to `complete` | The fast path still corrects it, so the two paths disagree | Follow the new rule in `encodeCallResult` |
| The "content and input requests" check also covers `requestState`, with a new message | The fast path returns the old message and accepts content plus `requestState` | Extend the check and the message |

None of these touch admission, policy, rate limits or the audit chain itself.
