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

New migration step `81` (free on this base) adds the CIMD security-policy columns; step `82` adds the
fork-only allowed-audience column (item 5 below).

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
5. **Allowed audiences of CIMD clients** (fork-only, not in the ported PR). The instance security
   settings carry a fourth CIMD field, `allowed_audience_project_ids` on
   `ClientIDMetadataDocumentSettings`: the projects a client resolved from a metadata document may
   request as an audience (`urn:zitadel:iam:org:project:id:{id}:aud`). It is replace-all through
   `SetSecuritySettings`, read through `GetSecuritySettings`, and changed one entry at a time through
   `AddClientIDMetadataDocumentAllowedAudience` / `RemoveClientIDMetadataDocumentAllowedAudience`,
   all under `iam.policy.write` (read: `iam.policy.read`), like the allowed-URL list. The ZITADEL
   project (`zitadel` or the instance's project ID) is refused. Durable names follow item 1: the
   set-event JSON tag is `client_id_metadata_document_allowed_audiences_ixcans_fork`, and the single
   add/remove events are fork-local types
   (`instance.policy.security.client_id_metadata_document.allowed_audience_ixcans_fork.{added,removed}`).
   The read model is the column `client_id_metadata_document_allowed_audiences` of
   `projections.security_policies3` (setup step `82`). Unlike the allowed URLs it takes no unique
   constraints: every reduction is idempotent, so a duplicate addition pushed concurrently leaves
   the project in the list once.
6. **Scope policy for CIMD clients** (fork-only). When an authorization request is created for a
   client resolved from a metadata document, `cimdScopeAndAudience`
   (`internal/api/oidc/client_metadata_scopes.go`, a pure rule table called from the CIMD branch of
   `createAuthRequestScopeAndAudience`) keeps `openid`, `profile`, `email` and the organization
   routing scopes; keeps a project audience scope only for a project on the list of item 5, never
   for the ZITADEL project (`zitadel` or the instance project ID), and fails the request with
   `invalid_scope` for any other audience; keeps `offline_access` only with a granted audience; and
   drops every other scope (roles, `projects:roles`, metadata, resource owner, IdP, org roles,
   `phone`, `address`, custom). This also closes a role read through `/userinfo`, which asserts the
   roles of every project an `...:aud` scope names whenever `projects:roles` is present. The
   `resource` parameter stays ignored and dynamic client registration is unchanged.
7. **Signed, short-lived tokens and two grants for CIMD clients** (fork-only;
   `internal/api/oidc/client_metadata_tokens.go`). A client resolved from a metadata document gets
   JWT access tokens (so a resource server needs no introspection credential), capped at one hour
   because a JWT cannot be revoked before `exp`, and ID tokens capped at five minutes; a shorter
   configured lifetime still applies. The access token lifetime is decided in the command layer from
   the instance OIDC settings, not from the client, so the cap reaches it through a variadic
   `command.OIDCSessionOption` (`WithMaxAccessTokenLifetime`, `internal/command/oidc_session_option.go`)
   that the code exchange and refresh handlers pass only for such a client (its client ID is an
   https URL, which no registered application can have). A document may declare only the
   `authorization_code` and `refresh_token` grants; one that lists implicit, device code or token
   exchange does not resolve (`invalid_client`). Registered and dynamically registered clients are
   unchanged (DCR stays opaque). The device flow is refused at both entry points: the token
   endpoint's grant check refuses `device_code`, and `Server.DeviceAuthorization` now refuses to start
   a device authorization for any client without the device code grant
   (`checkDeviceAuthorizationGrant`). The oidc library's legacy handler made that check; its server
   handler, which ZITADEL is served through, does not, so before this a client without the grant
   could still get a user code issued (it could never redeem the device code).
8. **Public-only document fetch** (fork-only; `internal/publicfetch`). The metadata document is no
   longer fetched through the shared HTTP client and its operator denylist, which Actions targets
   also use and which an operator may narrow so Actions can reach internal targets. `publicfetch.NewClient()`
   connects only to public unicast addresses on port 443 over TLS, judged at dial time on the
   resolved address (rebinding-safe), with no proxy and no redirects. The rule is the pure function
   `publicfetch.IsPublicUnicast` (`CheckAddress` adds the port): every block of the IANA IPv4 and IPv6
   special-purpose registries is refused whatever its "globally reachable" flag, plus IPv4 multicast
   and all IPv6 outside `2000::/3`; IPv4-mapped and NAT64 well-known-prefix (`64:ff9b::/96`)
   addresses are judged by their embedded IPv4 address, and `64:ff9b:1::/48` is refused. The table
   was checked against the registries on 2026-10-15; re-check it when IANA adds a block. The
   resolver keeps its injected-client seam (tests pass `httptest` clients); `op.go` passes the
   public-only client. The package is meant for any other fetch of a caller-named URL, such as a
   foreign issuer's published keys. The shared `HTTPClient.DenyList` (item 2) is unchanged.
9. **Loopback redirect URIs for CIMD clients** (fork-only;
   `internal/api/oidc/client_metadata_redirects.go`). The ported PR kept only redirect URIs on the
   `client_id`'s origin, so a desktop or command-line tool could not sign in. A document may now also
   list `http://127.0.0.1:{port}/{path}`, `http://[::1]:{port}/{path}` (any port at request time,
   RFC 8252 section 7.3; scheme, host, path and query must match) and `http://localhost:{port}/{path}`
   (exact match only). Every other non-origin URI is still dropped, and the origin rule is unchanged
   for non-loopback URIs. A client that lists a loopback URI is native, the type whose loopback
   redirects the oidc library accepts at all; because that library's native loopback matching
   compares only path and query, `Server.VerifyAuthRequest` first applies the strict rule
   (`verifyClientIDMetadataRedirectURI`) to clients whose ID is an https URL. Post-logout redirect URIs
   stay same-origin only.
10. **A metadata document client's sign-in completes** (fork-only; fixes the ported PR). When the login
   UI linked the user's session to the authorization request (`CreateCallback`), the command layer ran
   the project permission check, which looks the client up as a registered application by its client
   ID. A client resolved from a metadata document has no application row, so every such sign-in failed
   after the user had signed in and consented (`Errors.App.NotFound`). Such a client belongs to no
   project, so there is no project check to make: `LinkSessionToAuthRequest` now skips the check for a
   client ID that is a metadata document URL (`authRequestClientHasProject`,
   `internal/command/auth_request_client_id_metadata.go`), which no registered or dynamically registered
   application can have (their client IDs are generated). Every other client is checked as before.
   Whether the client may start a request at all is still decided by the instance's allowed URLs when
   the request is created, and again when the code is exchanged, since the token endpoint resolves the
   client from its document. The rest of the path after the link (code, token exchange, refresh,
   userinfo, revocation, end session) was traced for other lookups that need an application row and
   has none that fails.
11. **PKCE with S256 is required of metadata document clients** (fork-only;
   `internal/api/oidc/client_metadata_pkce.go`). The protocol layer checks a code verifier only when
   the authorization request carried a challenge, so a public client resolved from a document could
   complete a sign-in without PKCE, although the guide said it must use it. `Server.Authorize` now
   answers such a client's request without a `code_challenge`, or with the `plain` method (also the
   method when none is named), with `invalid_request` at the already validated redirect URI, before an
   auth request is created, and the code exchange refuses a code of such a client whose request
   carried no S256 challenge (`invalid_grant`), so no other path to the token endpoint can skip it.
   Registered and dynamically registered clients are unchanged.

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
