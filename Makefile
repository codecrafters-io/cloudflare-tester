.PHONY: build test copy_course_file

build:
	go build -o dist/tester ./cmd/tester

test:
	go test -count=1 -v ./internal/waf

copy_course_file:
	cp ../build-your-own-firewall/course-definition.yml internal/waf/course-definition.yml
