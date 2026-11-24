# Changelog

## [1.6.0](https://github.com/Guilherme-Ciano/tollkeeper/compare/v1.5.0...v1.6.0) (2026-11-24)


### Features

* **governance:** add stateless approval tokens (`tk-approval+jwt`), CEL `approval.*` four-eyes rules, and Ed25519-signed config+pin bundles ([4ffb27c](https://github.com/Guilherme-Ciano/tollkeeper/commit/4ffb27c5e0ccf66c89b5dfa5914c9ce56e216c2c))
* **policy:** add static upstream provenance metadata (`trust`, `classification`, `egress`, `impact`), CEL fields, and `_meta["tollkeeper.provenance"]` response stamps ([87f53e8](https://github.com/Guilherme-Ciano/tollkeeper/commit/87f53e8))
* **ratelimit:** add cost-based GCRA impact limits (`cost_expr` / `max_cost`) for memory and Redis backends ([87f53e8](https://github.com/Guilherme-Ciano/tollkeeper/commit/87f53e8))
* **gateway:** add opt-in stateless idempotency / anti-replay guard (`header`, `required`, `canonical_hash`) and adversarial security test suite ([b3a5fb4](https://github.com/Guilherme-Ciano/tollkeeper/commit/b3a5fb4))

### Bug Fixes

* **ci:** split GitHub Pages build/deploy jobs and pin `ossf/scorecard-action` to `v2.5.0` ([421012f](https://github.com/Guilherme-Ciano/tollkeeper/commit/421012fdbfd74abf6f3335e7d50fe1745e5e6cba))
* **security:** resolve CodeQL allocation overflow and user-input log alerts ([ccae695](https://github.com/Guilherme-Ciano/tollkeeper/commit/ccae69533f1d912fb28c9746dc0445dc727fc035))


### Features

* **gateway:** add opt-in stateless idempotency guard and adversarial security test suite ([4ffb27c](https://github.com/Guilherme-Ciano/tollkeeper/commit/4ffb27c5e0ccf66c89b5dfa5914c9ce56e216c2c))
* **gateway:** add opt-in stateless idempotency guard and adversarial security test suite ([ccae695](https://github.com/Guilherme-Ciano/tollkeeper/commit/ccae69533f1d912fb28c9746dc0445dc727fc035))
* **gateway:** add opt-in stateless idempotency guard and adversarial security test suite ([421012f](https://github.com/Guilherme-Ciano/tollkeeper/commit/421012fdbfd74abf6f3335e7d50fe1745e5e6cba))
* **gateway:** add opt-in stateless idempotency guard and adversarial security test suite ([1046fa8](https://github.com/Guilherme-Ciano/tollkeeper/commit/1046fa816fd37b61ffb509a0f3179c1af2a7c284))
* **gateway:** add opt-in stateless idempotency guard and adversarial security test suite ([fb7ebea](https://github.com/Guilherme-Ciano/tollkeeper/commit/fb7ebea246714b18fe6735b7e0a2d7c0fa715142))
* **gateway:** add opt-in stateless idempotency guard and adversarial security test suite ([6443203](https://github.com/Guilherme-Ciano/tollkeeper/commit/64432039b43198d759e00f532c79a70dd40f503c))
* **gateway:** add opt-in stateless idempotency guard and adversarial security test suite ([ec55179](https://github.com/Guilherme-Ciano/tollkeeper/commit/ec551790012b134aebc6eb360662673cdf4afb5e))
* **gateway:** add opt-in stateless idempotency guard and adversarial security test suite ([0ccaec9](https://github.com/Guilherme-Ciano/tollkeeper/commit/0ccaec9364e39a337433564d87eda3eebe05c6ce))
* **governance:** add stateless approval tokens (tk-approval+jwt) and Ed25519 signed bundles ([4ffb27c](https://github.com/Guilherme-Ciano/tollkeeper/commit/4ffb27c5e0ccf66c89b5dfa5914c9ce56e216c2c))
* **governance:** add stateless approval tokens (tk-approval+jwt) and Ed25519 signed bundles ([ccae695](https://github.com/Guilherme-Ciano/tollkeeper/commit/ccae69533f1d912fb28c9746dc0445dc727fc035))
* **governance:** add stateless approval tokens (tk-approval+jwt) and Ed25519 signed bundles ([421012f](https://github.com/Guilherme-Ciano/tollkeeper/commit/421012fdbfd74abf6f3335e7d50fe1745e5e6cba))
* **governance:** add stateless approval tokens (tk-approval+jwt) and Ed25519 signed bundles ([1046fa8](https://github.com/Guilherme-Ciano/tollkeeper/commit/1046fa816fd37b61ffb509a0f3179c1af2a7c284))
* **governance:** add stateless approval tokens (tk-approval+jwt) and Ed25519 signed bundles ([fb7ebea](https://github.com/Guilherme-Ciano/tollkeeper/commit/fb7ebea246714b18fe6735b7e0a2d7c0fa715142))
* **governance:** add stateless approval tokens (tk-approval+jwt) and Ed25519 signed bundles ([6443203](https://github.com/Guilherme-Ciano/tollkeeper/commit/64432039b43198d759e00f532c79a70dd40f503c))
* **governance:** add stateless approval tokens (tk-approval+jwt) and Ed25519 signed bundles ([ec55179](https://github.com/Guilherme-Ciano/tollkeeper/commit/ec551790012b134aebc6eb360662673cdf4afb5e))
* **governance:** add stateless approval tokens (tk-approval+jwt) and Ed25519 signed bundles ([0ccaec9](https://github.com/Guilherme-Ciano/tollkeeper/commit/0ccaec9364e39a337433564d87eda3eebe05c6ce))
* **policy:** add static upstream provenance metadata, CEL fields, and response provenance stamps ([4ffb27c](https://github.com/Guilherme-Ciano/tollkeeper/commit/4ffb27c5e0ccf66c89b5dfa5914c9ce56e216c2c))
* **policy:** add static upstream provenance metadata, CEL fields, and response provenance stamps ([ccae695](https://github.com/Guilherme-Ciano/tollkeeper/commit/ccae69533f1d912fb28c9746dc0445dc727fc035))
* **policy:** add static upstream provenance metadata, CEL fields, and response provenance stamps ([421012f](https://github.com/Guilherme-Ciano/tollkeeper/commit/421012fdbfd74abf6f3335e7d50fe1745e5e6cba))
* **policy:** add static upstream provenance metadata, CEL fields, and response provenance stamps ([1046fa8](https://github.com/Guilherme-Ciano/tollkeeper/commit/1046fa816fd37b61ffb509a0f3179c1af2a7c284))
* **policy:** add static upstream provenance metadata, CEL fields, and response provenance stamps ([fb7ebea](https://github.com/Guilherme-Ciano/tollkeeper/commit/fb7ebea246714b18fe6735b7e0a2d7c0fa715142))
* **policy:** add static upstream provenance metadata, CEL fields, and response provenance stamps ([6443203](https://github.com/Guilherme-Ciano/tollkeeper/commit/64432039b43198d759e00f532c79a70dd40f503c))
* **policy:** add static upstream provenance metadata, CEL fields, and response provenance stamps ([ec55179](https://github.com/Guilherme-Ciano/tollkeeper/commit/ec551790012b134aebc6eb360662673cdf4afb5e))
* **policy:** add static upstream provenance metadata, CEL fields, and response provenance stamps ([0ccaec9](https://github.com/Guilherme-Ciano/tollkeeper/commit/0ccaec9364e39a337433564d87eda3eebe05c6ce))
* **ratelimit:** add cost-based GCRA impact limits for memory and Redis backends ([4ffb27c](https://github.com/Guilherme-Ciano/tollkeeper/commit/4ffb27c5e0ccf66c89b5dfa5914c9ce56e216c2c))
* **ratelimit:** add cost-based GCRA impact limits for memory and Redis backends ([ccae695](https://github.com/Guilherme-Ciano/tollkeeper/commit/ccae69533f1d912fb28c9746dc0445dc727fc035))
* **ratelimit:** add cost-based GCRA impact limits for memory and Redis backends ([421012f](https://github.com/Guilherme-Ciano/tollkeeper/commit/421012fdbfd74abf6f3335e7d50fe1745e5e6cba))
* **ratelimit:** add cost-based GCRA impact limits for memory and Redis backends ([1046fa8](https://github.com/Guilherme-Ciano/tollkeeper/commit/1046fa816fd37b61ffb509a0f3179c1af2a7c284))
* **ratelimit:** add cost-based GCRA impact limits for memory and Redis backends ([fb7ebea](https://github.com/Guilherme-Ciano/tollkeeper/commit/fb7ebea246714b18fe6735b7e0a2d7c0fa715142))
* **ratelimit:** add cost-based GCRA impact limits for memory and Redis backends ([6443203](https://github.com/Guilherme-Ciano/tollkeeper/commit/64432039b43198d759e00f532c79a70dd40f503c))
* **ratelimit:** add cost-based GCRA impact limits for memory and Redis backends ([ec55179](https://github.com/Guilherme-Ciano/tollkeeper/commit/ec551790012b134aebc6eb360662673cdf4afb5e))
* **ratelimit:** add cost-based GCRA impact limits for memory and Redis backends ([0ccaec9](https://github.com/Guilherme-Ciano/tollkeeper/commit/0ccaec9364e39a337433564d87eda3eebe05c6ce))


### Documentation

* **security:** update threat model for v1.5+ and publish ADRs 0020-0022 ([4ffb27c](https://github.com/Guilherme-Ciano/tollkeeper/commit/4ffb27c5e0ccf66c89b5dfa5914c9ce56e216c2c))
* **security:** update threat model for v1.5+ and publish ADRs 0020-0022 ([ccae695](https://github.com/Guilherme-Ciano/tollkeeper/commit/ccae69533f1d912fb28c9746dc0445dc727fc035))
* **security:** update threat model for v1.5+ and publish ADRs 0020-0022 ([421012f](https://github.com/Guilherme-Ciano/tollkeeper/commit/421012fdbfd74abf6f3335e7d50fe1745e5e6cba))
* **security:** update threat model for v1.5+ and publish ADRs 0020-0022 ([1046fa8](https://github.com/Guilherme-Ciano/tollkeeper/commit/1046fa816fd37b61ffb509a0f3179c1af2a7c284))
* **security:** update threat model for v1.5+ and publish ADRs 0020-0022 ([fb7ebea](https://github.com/Guilherme-Ciano/tollkeeper/commit/fb7ebea246714b18fe6735b7e0a2d7c0fa715142))
* **security:** update threat model for v1.5+ and publish ADRs 0020-0022 ([6443203](https://github.com/Guilherme-Ciano/tollkeeper/commit/64432039b43198d759e00f532c79a70dd40f503c))
* **security:** update threat model for v1.5+ and publish ADRs 0020-0022 ([ec55179](https://github.com/Guilherme-Ciano/tollkeeper/commit/ec551790012b134aebc6eb360662673cdf4afb5e))
* **security:** update threat model for v1.5+ and publish ADRs 0020-0022 ([0ccaec9](https://github.com/Guilherme-Ciano/tollkeeper/commit/0ccaec9364e39a337433564d87eda3eebe05c6ce))

## [1.5.0](https://github.com/Guilherme-Ciano/tollkeeper/compare/v1.4.1...v1.5.0) (2026-11-24)


### Features

* **audit:** add RepairTail torn-tail recovery with tamper refusal and corruption tests ([7a5db01](https://github.com/Guilherme-Ciano/tollkeeper/commit/7a5db01dcd34dee41bea255eb109eb13c90d1c73))


### Security

* **egress:** add netguard private-IP dialer control and SSRF test suite ([c1483f4](https://github.com/Guilherme-Ciano/tollkeeper/commit/c1483f4b07f55ae09804526333804b9e5aeaa03c))


### Documentation

* **readme:** align roadmap version with v1.5.0 release ([fbb3c5b](https://github.com/Guilherme-Ciano/tollkeeper/commit/fbb3c5b6a33af2d909cfdb4e316faf22e09982ee))

## [1.4.1](https://github.com/Guilherme-Ciano/tollkeeper/compare/v1.4.0...v1.4.1) (2026-11-23)


### Bug fixes

* **release:** use .Prerelease template variable in GoReleaser Homebrew Cask ([8892658](https://github.com/Guilherme-Ciano/tollkeeper/commit/88926588f0b99553e230d336371b831a9640e46b))

## [1.4.0](https://github.com/Guilherme-Ciano/tollkeeper/compare/v1.3.0...v1.4.0) (2026-11-23)


### Features

* **cli:** add tollkeeper init command for local and team starter configs ([234a802](https://github.com/Guilherme-Ciano/tollkeeper/commit/234a80205404b726526f47a85e7934fa3eaaedc0))


### Documentation

* add 2-minute coding agent quickstart guide for Claude Code, Cursor and Copilot ([4171211](https://github.com/Guilherme-Ciano/tollkeeper/commit/417121118733865246de5e015dccf2ee620cb8d6))
* remove broken badges, update v1.3 benchmark summary, roadmap, and SECURITY.md ([28a781d](https://github.com/Guilherme-Ciano/tollkeeper/commit/28a781dda717011a50083bc9fa32cc14b03412c8))
* **site:** add Swiss-industrial interactive landing page and GitHub Pages workflow ([c622052](https://github.com/Guilherme-Ciano/tollkeeper/commit/c622052334d8b5b2d2315ca9c965abbc081b9bce))

## [1.3.0](https://github.com/Guilherme-Ciano/tollkeeper/compare/v1.2.0...v1.3.0) (2026-11-19)


### Features

* aggregate prompts and resources from upstreams ([7f53642](https://github.com/Guilherme-Ciano/tollkeeper/commit/7f53642a668e363a03cf2fed6116a2084e3f7db0))
* **app:** reload policy and rate limits on SIGHUP ([7f53642](https://github.com/Guilherme-Ciano/tollkeeper/commit/7f53642a668e363a03cf2fed6116a2084e3f7db0))
* **audit:** export committed records to an OTLP log collector ([7f53642](https://github.com/Guilherme-Ciano/tollkeeper/commit/7f53642a668e363a03cf2fed6116a2084e3f7db0))
* **authn:** RFC 7662 token introspection for opaque tokens ([7f53642](https://github.com/Guilherme-Ciano/tollkeeper/commit/7f53642a668e363a03cf2fed6116a2084e3f7db0))
* **deploy:** Grafana dashboard and Prometheus alert rules ([7f53642](https://github.com/Guilherme-Ciano/tollkeeper/commit/7f53642a668e363a03cf2fed6116a2084e3f7db0))
* **deploy:** Helm chart ([7f53642](https://github.com/Guilherme-Ciano/tollkeeper/commit/7f53642a668e363a03cf2fed6116a2084e3f7db0))
* **gateway:** subscriptions/listen with relayed list-changed notifications ([7f53642](https://github.com/Guilherme-Ciano/tollkeeper/commit/7f53642a668e363a03cf2fed6116a2084e3f7db0))
* **policy:** shadow rules and policy explain ([7f53642](https://github.com/Guilherme-Ciano/tollkeeper/commit/7f53642a668e363a03cf2fed6116a2084e3f7db0))


### Benchmarks

* republish the overhead benchmark for v1.3 ([7f53642](https://github.com/Guilherme-Ciano/tollkeeper/commit/7f53642a668e363a03cf2fed6116a2084e3f7db0))


### Chores

* release 1.3.0 ([ec9092d](https://github.com/Guilherme-Ciano/tollkeeper/commit/ec9092da93a874366d6ed7087ff8ebb4869dc2d0))

## [1.2.0](https://github.com/Guilherme-Ciano/tollkeeper/compare/v1.1.0...v1.2.0) (2026-11-19)


### Features

* Banner on readme docs ([#17](https://github.com/Guilherme-Ciano/tollkeeper/issues/17)) ([ee336bd](https://github.com/Guilherme-Ciano/tollkeeper/commit/ee336bd4abb7892eff1f8f45b0584918e3904606))

## [1.1.0](https://github.com/Guilherme-Ciano/tollkeeper/compare/v1.0.0...v1.1.0) (2026-11-15)


### Features

* **audit:** anchor signed checkpoints in a Rekor v2 transparency log ([85f077e](https://github.com/Guilherme-Ciano/tollkeeper/commit/85f077e4ab6ec02ddea42303046b2741d5faefdd))
* **audit:** prove anchor time with RFC 3161 timestamps ([754731d](https://github.com/Guilherme-Ciano/tollkeeper/commit/754731d307e17a29a7e845509a71e3206f10ebaf))
* **audit:** wire Rekor anchoring into the gateway and audit verify ([7652156](https://github.com/Guilherme-Ciano/tollkeeper/commit/7652156be3c0e39e4769e4bc5a9f3a68672f54a6))


### Bug fixes

* **audit:** close anchoring loop and suffix-rebuild gaps found in review ([9845a53](https://github.com/Guilherme-Ciano/tollkeeper/commit/9845a53bfa4366c7e9a6814a447e34cfdcd575e8))
* catalog deltas against the live snapshot, bare-mode policy tests ([#8](https://github.com/Guilherme-Ciano/tollkeeper/issues/8)) ([7715cdf](https://github.com/Guilherme-Ciano/tollkeeper/commit/7715cdf519f5461b4c343162a42c03392c22891e))
* v1.0.1 hardening (deps, CodeQL, pinned images, docs) ([#5](https://github.com/Guilherme-Ciano/tollkeeper/issues/5)) ([d03a1fa](https://github.com/Guilherme-Ciano/tollkeeper/commit/d03a1fa47d34ad64193724da4a9f1ae57eac107e))


### Documentation

* **audit:** ADR 0010, anchoring runbook, threat model; add receipt fuzzing and a live Rekor test ([b773228](https://github.com/Guilherme-Ciano/tollkeeper/commit/b773228eb0fd363efbbb0513504da62a383eeca9))

## 1.0.0 (2026-11-14)


### Features

* **app:** reload the pin lockfile and serve a pin report on the admin port ([aa9c71b](https://github.com/Guilherme-Ciano/tollkeeper/commit/aa9c71b417651864165248948b0c5cfc06a5060b))
* **app:** select the Redis rate limit store from configuration ([871018e](https://github.com/Guilherme-Ciano/tollkeeper/commit/871018e501aecb897c03136002da6cea71167a10))
* **audit:** let the gateway run without DDL rights on the audit database ([b20b0f5](https://github.com/Guilherme-Ciano/tollkeeper/commit/b20b0f52ca68c630dd47b2b5fc080d0070bd4dbc))
* **audit:** mirror every batch to a transactional sink ([74317fc](https://github.com/Guilherme-Ciano/tollkeeper/commit/74317fc2313c0eb1f70833c4929b680a07e0d408))
* **audit:** Postgres sink with append-only, self-verifying triggers ([e3f820c](https://github.com/Guilherme-Ciano/tollkeeper/commit/e3f820c3d45ab359aab1377ae935f2601e866f89))
* **bench:** mcpbench open-loop load generator and overhead harness ([8a54758](https://github.com/Guilherme-Ciano/tollkeeper/commit/8a54758ab4a32057d31cda34fb509c8e09449b75))
* **catalog:** allow unprefixed tool names when fronting a single upstream ([c19bc4a](https://github.com/Guilherme-Ciano/tollkeeper/commit/c19bc4a66e7c6e2bd562979ffe9db24122cdc253))
* **cli:** add pin status and pin approve with description diffs ([4c40e27](https://github.com/Guilherme-Ciano/tollkeeper/commit/4c40e27a11796508367a9d39acc48ab5642f27d5))
* **config:** log the SHA-256 of the loaded config at startup ([9a7214a](https://github.com/Guilherme-Ciano/tollkeeper/commit/9a7214a6644e212a368858dc28901dd73c07820d))
* configure the Postgres audit sink and verify chains stored in it ([0d9e9c0](https://github.com/Guilherme-Ciano/tollkeeper/commit/0d9e9c0dc21cdfb2da25cf925929ba2229602330))
* core domain packages for config, catalog, upstreams, policy, limits and audit ([a0785d4](https://github.com/Guilherme-Ciano/tollkeeper/commit/a0785d41fd8404be9991e47b92113071f572b660))
* **demo:** Go demo MCP servers, demo client and docker compose stack ([b9547bc](https://github.com/Guilherme-Ciano/tollkeeper/commit/b9547bccbffbfcb406fdaf61c868f982d540c02f))
* **gateway:** hide and refuse tools whose definition is not approved ([83d5d2a](https://github.com/Guilherme-Ciano/tollkeeper/commit/83d5d2ae6b0e0aafaf8cee89242824e05b8a9a3d))
* opt-in pprof endpoints on the admin listener ([c4619bd](https://github.com/Guilherme-Ciano/tollkeeper/commit/c4619bdd424bf36b540c07f515294b1428e508cb))
* **pin:** lockfile and guard for approved tool definitions ([f6a7f7b](https://github.com/Guilherme-Ciano/tollkeeper/commit/f6a7f7bbd4a29795b3a5349bb28b81122d668788))
* **ratelimit:** Redis GCRA backend behind a shared conformance suite ([1e6306e](https://github.com/Guilherme-Ciano/tollkeeper/commit/1e6306e191e2e1973a2b1c87ad7eeb963980f4ea))
* stateless MCP gateway with OAuth resource server and admission pipeline ([2eea313](https://github.com/Guilherme-Ciano/tollkeeper/commit/2eea3132d13442a08b2b4c56645c7e541b223292))


### Bug fixes

* **app:** report ready only once an upstream's catalog is synced ([7589880](https://github.com/Guilherme-Ciano/tollkeeper/commit/75898805ae598a62866b3bb23ebbc2de0fc50013))
* **audit:** fail closed on sink errors and reject logs without signatures ([942cc06](https://github.com/Guilherme-Ciano/tollkeeper/commit/942cc06d972ce50b6b5438e2a61e2d7a02f17ed4))
* **audit:** keep fsynced records on an ambiguous mirror commit and catch up ([1c5312d](https://github.com/Guilherme-Ciano/tollkeeper/commit/1c5312db04e01821b06817757acc2a7be756cdb5))
* **authn:** let concurrent cold-start requests join the in-flight JWKS fetch ([79a1bca](https://github.com/Guilherme-Ciano/tollkeeper/commit/79a1bca707cb38e887ca84c0ebe1a60ae7b119d1))
* **bench:** cap in-flight requests and record host CPU count ([8e5d3a6](https://github.com/Guilherme-Ciano/tollkeeper/commit/8e5d3a6e92eff0e026f4a74c687b13924ba9c4d1))
* **bench:** keep benchmark rate limits within the validated range ([7314436](https://github.com/Guilherme-Ciano/tollkeeper/commit/731443697fc658dc8749f048fd468f1749d2e090))
* **cli:** fail verification of an empty Postgres chain and report source errors apart ([9c4e74e](https://github.com/Guilherme-Ciano/tollkeeper/commit/9c4e74e3c0ff0f5d658be8a847514d8915787d88))
* **config:** ignore TOLLKEEPER_ variables that are not nested config keys ([2fe71d9](https://github.com/Guilherme-Ciano/tollkeeper/commit/2fe71d95778d16869210873f64827ad2c5b10a49))
* **gateway:** close case-folding bypass and bound attacker-controlled cost ([81357ec](https://github.com/Guilherme-Ciano/tollkeeper/commit/81357ecb373e4718240364f7d68ac01b170ff050))
* harden config, auth, catalog and telemetry from audit findings ([f0d5b3b](https://github.com/Guilherme-Ciano/tollkeeper/commit/f0d5b3bfea25c523f50f2e2928da74bb3b40da90))
* **pgsink:** reject out-of-range sequence numbers and surface rollback errors ([5eb0ee3](https://github.com/Guilherme-Ciano/tollkeeper/commit/5eb0ee37f23bc30badf03fbff639457ee86228da))
* round GCRA intervals up in Redis, stop sharing the lockfile map, refuse concurrent approvals ([d1d697c](https://github.com/Guilherme-Ciano/tollkeeper/commit/d1d697c5398f0e7f9ed455031e27ffc92371b467))
* **upstream:** backoff on crash loops, health probes and no credential leaks ([3e3d240](https://github.com/Guilherme-Ciano/tollkeeper/commit/3e3d240955873af290cacae6768fca2ba613859e))


### Security

* **app:** serve /pins only on a loopback admin listener or with a bearer token ([1c2730f](https://github.com/Guilherme-Ciano/tollkeeper/commit/1c2730f545da89330795149117fb14d4a19c42a2))
* **audit:** refuse signing keys readable by group or others ([7130e5c](https://github.com/Guilherme-Ciano/tollkeeper/commit/7130e5c91574c12e12f182a6835839f40b897a3c))
* **audit:** run without DDL by default and warn about excess database privileges ([bace55d](https://github.com/Guilherme-Ciano/tollkeeper/commit/bace55d8ffd2bee73ac915d6475b1fee7d6d979a))
* **cli:** confirm each approval and make hidden characters visible ([5139a47](https://github.com/Guilherme-Ciano/tollkeeper/commit/5139a479035cd244b431d1c0e1fb23b18e41dbd1))
* **gateway:** reject control characters in requested tool names ([f8cab07](https://github.com/Guilherme-Ciano/tollkeeper/commit/f8cab07205442c29b04a3f8aba25f024479e0a8f))
* **pgsink:** derive body from raw and bind columns inside the trigger ([fc21f58](https://github.com/Guilherme-Ciano/tollkeeper/commit/fc21f587c636d65a0091caaa9d5a476a65f73c3f))
* **pin:** hash the full tool definition and re-evaluate pins atomically ([55be530](https://github.com/Guilherme-Ciano/tollkeeper/commit/55be53024a5c9bbce1c5df0c88f217641f995ec8))
* **pin:** verify reports against their pinned definition and refuse exposed lockfiles ([8c5d45a](https://github.com/Guilherme-Ciano/tollkeeper/commit/8c5d45a56e8f01a5a2ce04fbbdb1ee425732ee0c))


### Documentation

* add a STRIDE threat model with trust boundaries and an ADR index ([1e17744](https://github.com/Guilherme-Ciano/tollkeeper/commit/1e17744d3855c4066db8a609bb32b171e9db56b8))
* add status badges and release verification guide ([276a36e](https://github.com/Guilherme-Ciano/tollkeeper/commit/276a36e344955034094f098315b4c21a7fc00f61))
* **adr:** explain the zero code comments rule and its trade-offs ([46ee214](https://github.com/Guilherme-Ciano/tollkeeper/commit/46ee2140f9b889c785266a6e79a9c2bd916ae4b7))
* **adr:** record policy, rate limiting, admission, token and transport decisions ([49221e1](https://github.com/Guilherme-Ciano/tollkeeper/commit/49221e1a51d69e3ea0afb6fd2488cb9d9b606feb))
* **adr:** record shared Redis limits and the immutable Postgres audit sink ([9be1c25](https://github.com/Guilherme-Ciano/tollkeeper/commit/9be1c251a1d7695bc2f443013f0236e129c3d515))
* describe the hardened pinning flow and update the threat model ([0dc4fb7](https://github.com/Guilherme-Ciano/tollkeeper/commit/0dc4fb7120e8a3f96742b9526cfcf32a3c2b109b))
* document tool pinning enforcement and record ADR 0007 ([a207f54](https://github.com/Guilherme-Ciano/tollkeeper/commit/a207f5465ab517a0f755f70e4d3e6be7e35d64f3))
* **examples:** GitHub and filesystem MCP server configurations, validated in tests ([35ece71](https://github.com/Guilherme-Ciano/tollkeeper/commit/35ece71218bcb128c1010e0911ad568a1cd0f4f5))
* LinkedIn post draft built on the measured overhead ([eba8a55](https://github.com/Guilherme-Ciano/tollkeeper/commit/eba8a55e73ad1877a01fde08cb2fbd52b1bfd9f0))
* note the BuildKit requirement for the compose demo ([83d0d6e](https://github.com/Guilherme-Ciano/tollkeeper/commit/83d0d6ecdc3ce703f4c6e98a4890e6a93c98bc27))
* README with architecture, demo walkthrough, security model and ADR 0001 ([1d5662d](https://github.com/Guilherme-Ciano/tollkeeper/commit/1d5662d992835c75ca2c878af9c5aabc58c01fef))
* **readme:** document pinning, Redis limits, the Postgres sink and the roadmap ([63f8de9](https://github.com/Guilherme-Ciano/tollkeeper/commit/63f8de921834b12d4dd510b57e57564604ffaa79))
* reflect review and audit fixes in README and ADR 0001 ([b976477](https://github.com/Guilherme-Ciano/tollkeeper/commit/b97647753adc3c493fb1f6931d5ce21e52fd1dd9))


### Benchmarks

* micro-benchmark results (count=10, serial packages) ([296dc06](https://github.com/Guilherme-Ciano/tollkeeper/commit/296dc062e8ffb57ff1ae1d6edee94449636994f7))
* publish end-to-end overhead results and profile analysis ([a08ac7e](https://github.com/Guilherme-Ciano/tollkeeper/commit/a08ac7e8758cb85728b39e10d04519e37cfc45b1))
