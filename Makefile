.PHONY: build test copy_course_file record_fixtures test_stage_1 test_stage_2 test_flakiness

build:
	go build -o dist/tester ./cmd/tester

test:
	go test -v ./internal/...

copy_course_file:
	cp ../build-your-own-cloudflare/course-definition.yml internal/test_helpers/course_definition.yml

record_fixtures:
	CODECRAFTERS_RECORD_FIXTURES=true go test -count=1 ./internal/... -run 'Test(BindToPort|ProxyAPI)'

define stage_1_test_cases
[{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_1: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_1_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

RUNS ?= 100

test_flakiness:
	go test -count=$(RUNS) ./internal/ -run '(TestBindToPort(Success|EarlyExit|OneRequest|OccupiedPort)|TestProxyAPI(Success|UnavailableOrigin))$$'

define stage_2_test_cases
[{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_2: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/proxy_api/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_2_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh
