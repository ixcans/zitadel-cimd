# ixcans/zitadel-cimd

A plain (non-GitHub-"Fork") clone of [zitadel/zitadel](https://github.com/zitadel/zitadel)
at `v4.19.4`, with Client ID Metadata Document (CIMD, [RFC pending], aka "client_id as an
HTTPS URL") support ported from the community PR
[zitadel/zitadel#12860](https://github.com/zitadel/zitadel/pull/12860) ("feat-oidc-cimd-allowlist"),
which upstream has not merged. AGPL-3.0, same as upstream; full modified source is public here,
satisfying §13.

## What changed vs. v4.19.4

The 24 commits from PR #12860 (`merge-base` `ab3b44cd74`..`1e5c347d29` against upstream `main`),
cherry-picked onto `v4.19.4` in original order. Six files specific to upstream `main`'s (v5-only)
relational-storage rewrite, which v4.19.4 does not have and does not need for CIMD, were dropped:
`backend/v3/domain/settings.go` + its mock, `backend/v3/storage/database/repository/settings{,_test}.go`,
`internal/query/projection/{relational_table,settings_relational}.go`. Everything else applied
cleanly or with small conflict resolution (`go.mod`'s unrelated dependency drift from v5's full
tree reverted to this fork's existing versions; the real `zitadel/oidc` v3.47.5→v3.48.0 bump kept).

New migration step `81` (free on this base) adds the CIMD security-policy columns.

### Fork-specific hardening beyond the ported PR

1. **Durable-event field names are fork-local.** The three CIMD fields on
   `instance.SecurityPolicySetEvent` (`internal/repository/instance/policy_security.go`) carry
   `_ixcans_fork`-suffixed JSON tags, not the plain names the upstream PR uses. That event payload
   is durable eventstore history, replayed forever. If this instance ever ran stock
   `zitadel/zitadel` and upstream later ships its own CIMD support under these same plain names but
   different semantics (e.g. allow-any-URL by default, no instance-level allowlist), a past `true`
   from this fork would otherwise be silently reinterpreted under upstream's looser rules. The
   fork-local tags make that impossible: stock code has no field to bind them to, so an unknown
   field is dropped on unmarshal (fails closed), never re-widened. The read-model projection
   columns and the public gRPC/proto field names were left unchanged — they're rebuildable /
   our own API surface, not durable-replay hazards.
2. **NAT64 added to the SSRF denylist** (`cmd/defaults.yaml` and `cmd/mirror/defaults.yaml`,
   `HTTPClient.DenyList`). Upstream's default denylist is pure literal-CIDR matching on the
   resolved IP (RFC1918/loopback/link-local/CGNAT + their IPv6 equivalents) with zero NAT64
   awareness. This fleet's cluster is IPv6-only with native NAT64/DNS64 egress under the
   well-known prefix `64:ff9b::/96` (RFC 6052): an AAAA record embedding a denied IPv4 address in
   that prefix (e.g. `64:ff9b::a9fe:a9fe` = 169.254.169.254, or `64:ff9b::7f00:1` = 127.0.0.1) is
   not contained in any of upstream's four IPv6 entries, so it would bypass the denylist
   undetected. Added `64:ff9b::/96` to both config files' `DenyList`.
3. **Adjacent gap fixed for consistency**: `cmd/mirror/defaults.yaml` already blocked IPv4-mapped
   IPv6 (`::ffff:0:0/96`); `cmd/defaults.yaml` (the live server's own config) did not. Added it
   there too - this was an inconsistency between the two configs, not a deliberate choice.
4. **Fork-distinct build version**: CI bakes the git tag (`v4.19.4-cimd.1`, `v4.19.4-cimd.2`, ...)
   into `cmd/build.version` via the same `-X` ldflag upstream's own `pack-platform` nx target
   uses, so `zitadel --version` always identifies this exact fork/build, never confusable with a
   stock v4.19.4 binary.

### CI

Upstream's full workflow suite (lint, unit/integration tests, CodeQL, issue triage,
semantic-release, Homebrew/chart-bump triggers, npm package publish) was removed. This repo has
two workflows, both on GitHub-hosted `ubuntu-latest` only - never pointed at any
internal/self-hosted runner fleet, since this is a third-party-derived fork:

- `.github/workflows/test.yml` runs on every push to a branch and every pull request: the same
  codegen the image build runs, then `go vet` and the module's unit tests (`./...`, about five
  minutes in all). `go vet` skips two packages whose findings are in upstream v4.19.4 itself and
  outside the fork's patches: `internal/crypto/database` and `internal/v2/database`. The tests
  skip `TestCommandSide_TestSMTPConfig` and `TestCommandSide_TestSMTPConfigById`, which dial real
  third-party SMTP servers with no timeout and hung a run for 30 minutes. The integration tests
  (`//go:build integration`) need a running instance and are not run, and neither is `-race`.
- `.github/workflows/build-publish.yml` compiles the API binary for `linux/amd64` and publishes
  `ghcr.io/ixcans/zitadel-cimd`. It needs `test.yml` to pass first.

### Publishing rule

Publishing is tag-driven; a push to `main` (or any branch) publishes nothing.

- Tags are `v<upstream version>-cimd.<n>`, for example `v4.19.4-cimd.2`. The workflow takes the
  image tag and the baked-in build version from the git tag, and also tags the image
  `sha-<commit>`.
- Tags are immutable. The workflow refuses to publish a version that already exists in the
  registry, so a deployment pinned to a tag keeps running the image it was verified against.
  To change what a deployment runs, cut the next `-cimd.<n>` tag and move the pin.
- `latest` is not maintained. It still points at the last build made before publishing became
  tag-driven (the same image as `v4.19.4-cimd.1`); do not deploy it.
- `workflow_dispatch` re-runs the publish for an existing tag (`gh workflow run build-publish.yml
  --ref <tag>`) and fails on a branch. There is no version input.

### Review status of the ported PR (as of 2026-10-06)

At cherry-pick time, PR #12860 had 24 commits and all 29 Copilot review threads resolved,
including the two most safety-relevant findings: an unbounded-hang risk in the detached
resolution path (fixed upstream in `bf9f3b49a`, carried into this port) and a bypass of the
2048-byte URL limit via the replace-all settings RPC (also fixed in `bf9f3b49a`). No human
maintainer has reviewed the PR (`reviewDecision: REVIEW_REQUIRED`) and it is still being
actively revised upstream - re-diff before merging any future update from it.
