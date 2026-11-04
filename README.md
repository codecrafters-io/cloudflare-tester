# firewall-tester

Tester for the "Build your own AI Firewall" course, with slug `firewall`. Keep
this repository beside `build-your-own-firewall`.

```sh
make copy_course_file
make test
make test_stage_1
make test_stage_2
make test_stage_3
make test_stage_4
```

`TestStagesMatchYAML` checks the course and tester registrations. Stage 1
(`fi6`) starts the learner program with the three startup flags, writes an empty
policy, and checks two direct HTTP 200 responses from GET /health on port 8080
within five seconds. It runs from a temporary directory and stops the process
group on both success and failure. A pre-existing listener on port 8080 is
reported as a tester setup error.

Offline scenarios under `internal/test_helpers/scenarios/base/` cover correct
and delayed servers, slow responses, response bodies, early exits, wrong status
codes, redirects, missing listeners, hung responses, and a server that exits
after one request. The fixtures under `internal/test_helpers/fixtures/base/`
preserve learner logs and verdicts. Only temporary policy paths are normalized.

```sh
make record_fixtures
make test_flakiness RUNS=100
```

The flakiness target repeats stage-1 lifecycle cases and stage-2 success and
unavailable-origin cases, plus stage-3 success and origin-leak regressions, plus
stage-4 success, bounded-decoding, and preservation cases. The full suite also
checks startup timeouts and port cleanup. Python 3 and Go 1.25 are required for
local fixture tests. No model API or paid service is used.

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
before they reach the origin, and reports the rule in a JSON HTTP 403 error. Log
mode forwards matches unchanged and exposes `X-Firewall-Match` on the response.
Tests count origin requests and include a short post-denial observation window
to catch delayed forwarding. Matching is literal and case-sensitive.

The `scenarios/base/block_and_log/` reference passes all three implemented
stages. Its regressions cover leaked requests, policy parsing and message
boundaries, incorrect errors, log-mode enforcement, missing or stale headers,
and changed traffic. `make test_stage_3` runs all implemented stages. Raw
response bytes are captured before SDK decoding so trailing data cannot silently
pass.

Stage 4 (`wt4`) enables normalization when the policy includes `normalization`.
It applies NFKC, full Unicode case folding, zero-width removal, the supplied
homoglyph map, and one layer of whole-string base64 decoding. Inspection never
rewrites forwarded traffic. Policies without normalization retain literal
matching.

The `scenarios/base/defeat_evasion/` reference passes all four implemented
stages. Its focused regressions omit individual transforms, substitute
lowercasing, hardcode mappings, corrupt encoded text before decoding, recurse,
or rewrite requests. Only allocated addresses and temporary policy paths are
normalized in fixture comparisons, preserving the evasion evidence.
`make test_stage_4` runs all implemented stages.

Stages 5-8 add weighted heuristics, classifier calls, per-message threshold
decisions, and bidirectional data loss prevention. Stage 6 accepts sequential
classifier calls, with a 200 ms timeout per call and one fixed fallback to
denylist and heuristic decisions when classification is unavailable. It has no
concurrency benchmark, shared batch deadline, or configurable failure modes.
Stage 8 (`qe5`) redacts
supplied patterns in message content with request-scoped numbered placeholders
and buffers non-streaming responses before checking for a canary. Its reference
passes all eight implemented stages. Run `make test_stage_8` to exercise the
complete course so far, or
`go test -count=1 ./internal/ -run 'Test(StopDataLeaks|DLP)'` for its focused
regression and grader checks. Fixtures use local mocks and dummy values.

Stage 9 (`ou9`) adds incremental SSE inspection using a character-based canary
holdback. Clean streams retain all text, and blocked streams emit one terminal
error without releasing marker fragments. The official SDK checks text and
termination, with raw wire capture catching extra events after the SDK stops.
Run `make test_stage_9` for all nine stages, or
`go test -count=1 ./internal/ -run 'Test(InspectStreams|Stream)'` for focused
streaming and grader checks. The latency fixture spans two seconds and requires
first nonempty text within one second.

Stage 10 (`as4`) adds trusted tool-name allowlists, parsed URL destination
checks, and whole-batch authorization of assembled streamed calls. Approved IDs,
names and argument strings are preserved, while a denied batch exposes no action
fragments. Safe text still streams incrementally. Run `make test_stage_10` for
all ten stages, or
`go test -count=1 ./internal/ -run 'Test(GuardToolCalls|Tool)'` for focused tool
and grader checks. No tool is executed by these local fixtures.

Stage 11 (`mu9`) adds private-field export authorization using trusted policy
and producing call IDs. Its synthetic finale blocks a streamed base64 record
sent to an otherwise allowed browsing host. A 25-attack, 15-benign replay
reports observed course-suite outcomes. Additional controls cover changed
policies, request isolation, redaction, private diagnostics and atomic streamed
denial. Run `make test_stage_11` for all eleven stages, or
`go test -count=1 ./internal/ -run 'Test(StopExfiltration|Export)'` for focused
reference, broken-implementation and deterministic grader checks.

The top-level `internal/test_helpers/pass_all/` launcher requires an external
`ai-firewall` executable. Use the per-stage Make targets for the checked-in
local references. No live model or real tool execution is part of these
fixtures.

The release launcher is `test.sh`. The publish workflow runs on `v*` tags and
builds Linux amd64 and arm64 archives. Course SDK downloads the amd64 archive
from the
[latest published release](https://github.com/codecrafters-io/firewall-tester/releases/latest).
The release archives include both `tester` and `test.sh`.
