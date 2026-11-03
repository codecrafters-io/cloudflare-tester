.PHONY: build test copy_course_file record_fixtures test_stage_1 test_stage_2 test_stage_3 test_stage_4 test_stage_5 test_stage_6 test_stage_7 test_stage_8 test_stage_9 test_stage_10 test_stage_11 test_flakiness

build:
	go build -o dist/tester ./cmd/tester

test:
	go test -v ./internal/...

copy_course_file:
	cp ../build-your-own-cloudflare/course-definition.yml internal/test_helpers/course_definition.yml

record_fixtures:
	CODECRAFTERS_RECORD_FIXTURES=true go test -count=1 ./internal/... -run 'Test(BindToPort|ProxyAPI|BlockAndLog|DefeatEvasion|ScoreWithHeuristics|CallClassifier|DecideWithThresholds|StopDataLeaks|InspectStreams|GuardToolCalls|StopExfiltration)'

define stage_1_test_cases
[{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_1: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_1_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

RUNS ?= 100

test_flakiness:
	go test -count=$(RUNS) ./internal/ -run '(TestBindToPort(Success|EarlyExit|OneRequest|OccupiedPort)|TestProxyAPI(Success|UnavailableOrigin)|TestBlockAndLog(PassAll|LeakBeforeBlock|LeakAfterBlock)|TestDefeatEvasion(PassAll|RecursiveDecode|RewriteRequest)|TestScoreWithHeuristics(PassAll|RepeatWeight|LogBlocks)|TestCallClassifier(PassAll|Sequential|NoTimeout)|TestDecideWithThresholds(PassAll|RequestWideHeuristics|IgnoreToolRole)|TestStopDataLeaks(PassAll|ReuseValues|RawOnlyCanary)|TestInspectStreams(PassAll|NoHold|ByteHold)|TestGuardToolCalls(PassAll|SubstringHost|StreamNonAtomic)|TestStopExfiltration(PassAll|SkipQueryValues|TrustResultName))$$'

define stage_2_test_cases
[{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_2: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/proxy_api/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_2_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

define stage_3_test_cases
[{"slug":"kg7","tester_log_prefix":"stage-3","title":"Stage #3: Block and log"},{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_3: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/block_and_log/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_3_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

define stage_4_test_cases
[{"slug":"wt4","tester_log_prefix":"stage-4","title":"Stage #4: Defeat evasion"},{"slug":"kg7","tester_log_prefix":"stage-3","title":"Stage #3: Block and log"},{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_4: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/defeat_evasion/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_4_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

define stage_5_test_cases
[{"slug":"ro3","tester_log_prefix":"stage-5","title":"Stage #5: Score with heuristics"},{"slug":"wt4","tester_log_prefix":"stage-4","title":"Stage #4: Defeat evasion"},{"slug":"kg7","tester_log_prefix":"stage-3","title":"Stage #3: Block and log"},{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_5: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/score_with_heuristics/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_5_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

define stage_6_test_cases
[{"slug":"xd5","tester_log_prefix":"stage-6","title":"Stage #6: Call the classifier"},{"slug":"ro3","tester_log_prefix":"stage-5","title":"Stage #5: Score with heuristics"},{"slug":"wt4","tester_log_prefix":"stage-4","title":"Stage #4: Defeat evasion"},{"slug":"kg7","tester_log_prefix":"stage-3","title":"Stage #3: Block and log"},{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_6: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/call_classifier/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_6_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

define stage_7_test_cases
[{"slug":"si3","tester_log_prefix":"stage-7","title":"Stage #7: Decide with thresholds"},{"slug":"xd5","tester_log_prefix":"stage-6","title":"Stage #6: Call the classifier"},{"slug":"ro3","tester_log_prefix":"stage-5","title":"Stage #5: Score with heuristics"},{"slug":"wt4","tester_log_prefix":"stage-4","title":"Stage #4: Defeat evasion"},{"slug":"kg7","tester_log_prefix":"stage-3","title":"Stage #3: Block and log"},{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_7: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/decide_with_thresholds/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_7_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

define stage_8_test_cases
[{"slug":"qe5","tester_log_prefix":"stage-8","title":"Stage #8: Stop data leaks"},{"slug":"si3","tester_log_prefix":"stage-7","title":"Stage #7: Decide with thresholds"},{"slug":"xd5","tester_log_prefix":"stage-6","title":"Stage #6: Call the classifier"},{"slug":"ro3","tester_log_prefix":"stage-5","title":"Stage #5: Score with heuristics"},{"slug":"wt4","tester_log_prefix":"stage-4","title":"Stage #4: Defeat evasion"},{"slug":"kg7","tester_log_prefix":"stage-3","title":"Stage #3: Block and log"},{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_8: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/stop_data_leaks/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_8_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

define stage_9_test_cases
[{"slug":"ou9","tester_log_prefix":"stage-9","title":"Stage #9: Inspect streams"},{"slug":"qe5","tester_log_prefix":"stage-8","title":"Stage #8: Stop data leaks"},{"slug":"si3","tester_log_prefix":"stage-7","title":"Stage #7: Decide with thresholds"},{"slug":"xd5","tester_log_prefix":"stage-6","title":"Stage #6: Call the classifier"},{"slug":"ro3","tester_log_prefix":"stage-5","title":"Stage #5: Score with heuristics"},{"slug":"wt4","tester_log_prefix":"stage-4","title":"Stage #4: Defeat evasion"},{"slug":"kg7","tester_log_prefix":"stage-3","title":"Stage #3: Block and log"},{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_9: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/inspect_streams/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_9_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

define stage_10_test_cases
[{"slug":"as4","tester_log_prefix":"stage-10","title":"Stage #10: Guard tool calls"},{"slug":"ou9","tester_log_prefix":"stage-9","title":"Stage #9: Inspect streams"},{"slug":"qe5","tester_log_prefix":"stage-8","title":"Stage #8: Stop data leaks"},{"slug":"si3","tester_log_prefix":"stage-7","title":"Stage #7: Decide with thresholds"},{"slug":"xd5","tester_log_prefix":"stage-6","title":"Stage #6: Call the classifier"},{"slug":"ro3","tester_log_prefix":"stage-5","title":"Stage #5: Score with heuristics"},{"slug":"wt4","tester_log_prefix":"stage-4","title":"Stage #4: Defeat evasion"},{"slug":"kg7","tester_log_prefix":"stage-3","title":"Stage #3: Block and log"},{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_10: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/guard_tool_calls/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_10_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh

define stage_11_test_cases
[{"slug":"mu9","tester_log_prefix":"stage-11","title":"Stage #11: Stop the exfiltration"},{"slug":"as4","tester_log_prefix":"stage-10","title":"Stage #10: Guard tool calls"},{"slug":"ou9","tester_log_prefix":"stage-9","title":"Stage #9: Inspect streams"},{"slug":"qe5","tester_log_prefix":"stage-8","title":"Stage #8: Stop data leaks"},{"slug":"si3","tester_log_prefix":"stage-7","title":"Stage #7: Decide with thresholds"},{"slug":"xd5","tester_log_prefix":"stage-6","title":"Stage #6: Call the classifier"},{"slug":"ro3","tester_log_prefix":"stage-5","title":"Stage #5: Score with heuristics"},{"slug":"wt4","tester_log_prefix":"stage-4","title":"Stage #4: Defeat evasion"},{"slug":"kg7","tester_log_prefix":"stage-3","title":"Stage #3: Block and log"},{"slug":"tf0","tester_log_prefix":"stage-2","title":"Stage #2: Proxy the API"},{"slug":"fi6","tester_log_prefix":"stage-1","title":"Stage #1: Bind to a port"}]
endef

test_stage_11: build
	CODECRAFTERS_REPOSITORY_DIR=$(shell pwd)/internal/test_helpers/scenarios/base/stop_exfiltration/pass_all \
	CODECRAFTERS_TEST_CASES_JSON='$(stage_11_test_cases)' \
	TESTER_DIR=$(shell pwd)/dist ./test.sh
