# cloudflare-tester

Tester for the "Build your own AI Firewall" course, with slug `cloudflare`.
Keep this repository beside `build-your-own-cloudflare`.

```sh
make copy_course_file
make test
make test_stage_1
make test_stage_2
make test_stage_3
make test_stage_4
```

`TestStagesMatchYAML` checks the course and tester registrations. Stage 1 (`fi6`)
starts the learner program with the three startup flags, writes an empty policy,
and checks two direct HTTP 200 responses from GET /health on port 8080 within
five seconds. It runs from a temporary directory and stops the process group on
both success and failure. A pre-existing listener on port 8080 is reported as a
tester setup error.

Offline scenarios under `internal/test_helpers/scenarios/base/` cover correct and
delayed servers, slow responses, response bodies, early exits, wrong status codes,
redirects, missing listeners, hung responses, and a server that exits after one
request. The fixtures under `internal/test_helpers/fixtures/base/` preserve learner
logs and verdicts. Only temporary policy paths are normalized.

```sh
make record_fixtures
make test_flakiness RUNS=100
```

The flakiness target repeats stage-1 lifecycle cases and stage-2 success and
unavailable-origin cases, plus stage-3 success and origin-leak regressions, plus stage-4 success, bounded-decoding, and preservation cases. The full suite
also checks startup timeouts and port cleanup. Python 3 and Go 1.25 are required
for local fixture tests. No model API or paid service is used.

Stage 2 (`tf0`) uses the official OpenAI Go SDK against a local mock origin. Its
four cases cover a basic completion, full conversation context and optional
fields, an origin HTTP 400, and an unavailable origin. The tester compares body
bytes at both ends, checks origin-host routing and authentication, and verifies
response headers. SDK retries are disabled and each call has a three-second
limit. The SDK is pinned to v3.74.0 for the existing Go 1.25 toolchain.

Stage-2 regressions under `scenarios/base/proxy_api/` include missing proxy
behavior, wrong origin host, dropped authentication, changed or extra bodies,
dropped response headers, a swallowed origin error, the wrong gateway status,
and a hung request. The `proxy_api/pass_all` reference implements both completed
stages. Only its allocated origin address and temporary policy paths are
normalized. No external model is contacted.

Stage 3 (`kg7`) reads a supplied `mode` and `denylist`, blocks matched prompts
before they reach the origin, and reports the rule in a JSON HTTP 403 error.
Log mode forwards matches unchanged and exposes `X-Firewall-Match` on the
response. Tests count origin requests and include a short post-denial observation
window to catch delayed forwarding. Matching is literal and case-sensitive.

The `scenarios/base/block_and_log/` reference passes all three implemented stages.
Its regressions cover leaked requests, policy parsing and message boundaries,
incorrect errors, log-mode enforcement, missing or stale headers, and changed
traffic. `make test_stage_3` runs all implemented stages. Raw response bytes are
captured before SDK decoding so trailing data cannot silently pass.

Stage 4 (`wt4`) enables normalization when the policy includes `normalization`.
It applies NFKC, full Unicode case folding, zero-width removal, the supplied
homoglyph map, and one layer of whole-string base64 decoding. Inspection never
rewrites forwarded traffic. Policies without normalization retain literal matching.

The `scenarios/base/defeat_evasion/` reference passes all four implemented stages.
Its focused regressions omit individual transforms, substitute lowercasing,
hardcode mappings, corrupt encoded text before decoding, recurse, or rewrite
requests. Only allocated addresses and temporary policy paths are normalized in
fixture comparisons, preserving the evasion evidence. `make test_stage_4` runs
all implemented stages.

Stages 5-11 remain stubs. The top-level `internal/test_helpers/pass_all/` launcher
still requires an external `ai-firewall` executable and does not validate those
stages. Use `make test_stage_1` or `make test_stage_2` for the implemented references.

The release launcher is `test.sh`. The publish workflow runs on `v*` tags. Publish
the first release (`v1`) before course CI attempts to download it. A tester release
has not been published yet.
