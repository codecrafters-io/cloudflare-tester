# cloudflare-tester

Tester for the "Build your own AI Firewall" course, with slug `cloudflare`.
Keep this repository beside `build-your-own-cloudflare`.

```sh
make copy_course_file
make test
make test_stage_1
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

The flakiness target repeats the success, process-exit, and occupied-port cases. The full suite
also checks startup timeouts and port cleanup. Python 3 and Go 1.25 are required
for local fixture tests. No model API or paid service is used.

Stages 2-11 remain stubs. The top-level `internal/test_helpers/pass_all/` launcher
still requires an external `ai-firewall` executable and does not validate those
stages. Use `make test_stage_1` for the implemented base-stage reference.

The release launcher is `test.sh`. The publish workflow runs on `v*` tags. Publish
the first release (`v1`) before course CI attempts to download it. This stage-1
change has not been committed or released.
