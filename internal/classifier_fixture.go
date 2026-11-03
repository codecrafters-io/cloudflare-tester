package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/codecrafters-io/tester-utils/test_case_harness"
)

// All classifier responses in this stage are labeled synthetic teaching data.
type classifierReply struct {
	score  int
	status int
	delay  time.Duration
	body   string
	drip   bool
}

type classifierExpectation struct {
	replies     []classifierReply
	unavailable bool
	above       bool
	threshold   int
	timing      string
	deadline    bool
}

type classifierRequest struct {
	method, path, contentType, authorization string
	body                                     []byte
}

type classifierFixture struct {
	url           string
	close         func()
	lock          sync.Mutex
	replies       map[string]classifierReply
	requests      []classifierRequest
	expected      []json.RawMessage
	offset        int
	singleLatency time.Duration
	down          bool
}

func newClassifierFixture() *classifierFixture {
	fixture := &classifierFixture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.lock.Lock()
		down := fixture.down
		fixture.lock.Unlock()
		if down {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				connection.Close()
			}
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		key, _ := canonicalMessage(body)
		fixture.lock.Lock()
		fixture.requests = append(fixture.requests, classifierRequest{r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), body})
		reply, found := fixture.replies[key]
		fixture.lock.Unlock()
		if !found {
			http.Error(w, "unexpected classifier message", http.StatusBadRequest)
			return
		}
		if reply.delay > 0 {
			select {
			case <-time.After(reply.delay):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if reply.status == 307 {
			w.Header().Set("Location", fixture.url+"/retry")
		}
		if reply.status != 0 {
			w.WriteHeader(reply.status)
		}
		if reply.drip {
			io.WriteString(w, `{"score":`)
			w.(http.Flusher).Flush()
			// Bytes arrive faster than a socket timeout; the whole-call deadline must still expire.
			for range 10 {
				select {
				case <-time.After(80 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
				if _, err := io.WriteString(w, " "); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
			io.WriteString(w, "92}")
		} else if reply.body != "" {
			io.WriteString(w, reply.body)
		} else {
			fmt.Fprintf(w, `{"score":%d}`, reply.score)
		}
	}))
	fixture.url, fixture.close = server.URL, server.Close
	return fixture
}

func canonicalMessage(body []byte) (string, error) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return "", err
	}
	result, err := json.Marshal(value)
	return string(result), err
}

// Compare a multiset so parallel arrival order is irrelevant and duplicates remain visible.
func checkClassifierRequests(requests []classifierRequest, expected []json.RawMessage) error {
	if len(requests) != len(expected) {
		return fmt.Errorf("expected %d classifier requests, got %d; score every message once before deciding", len(expected), len(requests))
	}
	wanted := make([]string, len(expected))
	actual := make([]string, len(requests))
	for i, message := range expected {
		key, err := canonicalMessage(message)
		if err != nil {
			return err
		}
		wanted[i] = key
	}
	for i, request := range requests {
		contentType, _, _ := mime.ParseMediaType(request.contentType)
		if request.method != http.MethodPost || request.path != "/classify" || contentType != "application/json" || request.authorization != "" {
			return fmt.Errorf("send POST /classify with Content-Type application/json and no origin Authorization; got method=%q path=%q Content-Type=%q Authorization=%q", request.method, request.path, request.contentType, request.authorization)
		}
		key, err := canonicalMessage(request.body)
		if err != nil {
			return fmt.Errorf("classifier request must contain one original message JSON object, got %+q", request.body)
		}
		actual[i] = key
	}
	slices.Sort(wanted)
	slices.Sort(actual)
	if !reflect.DeepEqual(wanted, actual) {
		return fmt.Errorf("send each original message object to --detector exactly once, preserving roles and content: expected %q, got %q", wanted, actual)
	}
	return nil
}

func checkClassifierHeaders(headers http.Header, expected classifierExpectation) error {
	status := "ok"
	if expected.unavailable {
		status = "unavailable"
	}
	if headers.Get("X-Firewall-Detector-Status") != status {
		return fmt.Errorf("expected X-Firewall-Detector-Status=%q, got %q", status, headers.Get("X-Firewall-Detector-Status"))
	}
	value := headers.Get("X-Firewall-Classifier-Score")
	if expected.unavailable {
		if value != "" {
			return fmt.Errorf("discard classifier scores after any detector failure, got X-Firewall-Classifier-Score=%q", value)
		}
		return nil
	}
	score, err := strconv.Atoi(value)
	if err != nil || score < 0 || score > 100 {
		return fmt.Errorf("expected an integer X-Firewall-Classifier-Score in 0..100, got %q", value)
	}
	if (score >= expected.threshold) != expected.above {
		return fmt.Errorf("classifier score is on the wrong side of policy threshold %d: got %d", expected.threshold, score)
	}
	return nil
}

func (fixture *classifierFixture) prepare(h *test_case_harness.TestCaseHarness, body []byte, testCase policyCase) error {
	expected := testCase.classifier
	if expected == nil {
		return fmt.Errorf("tester setup: missing classifier expectation for %s", testCase.name)
	}
	var request struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return err
	}
	fixture.expected = request.Messages
	fixture.lock.Lock()
	fixture.offset = len(fixture.requests)
	fixture.replies = map[string]classifierReply{}
	if !fixture.down && len(expected.replies) != len(request.Messages) {
		fixture.lock.Unlock()
		return fmt.Errorf("tester setup: classifier replies must match message count")
	}
	for i, message := range request.Messages {
		if fixture.down {
			break
		}
		key, err := canonicalMessage(message)
		if err != nil {
			fixture.lock.Unlock()
			return err
		}
		fixture.replies[key] = expected.replies[i]
	}
	fixture.lock.Unlock()
	h.Logger.Infof("[%s] Synthetic classifier fixtures: one POST /classify per original message, timeout 200ms", testCase.name)
	for i, reply := range expected.replies {
		body := reply.body
		if body == "" {
			body = fmt.Sprintf(`{"score":%d}`, reply.score)
		}
		status := reply.status
		if status == 0 {
			status = 200
		}
		h.Logger.Infof("[%s] Classifier message %d: HTTP %d, body=%+q, delay=%dms, drip=%t", testCase.name, i+1, status, body, reply.delay.Milliseconds(), reply.drip)
	}
	if fixture.down {
		h.Logger.Infof("[%s] Classifier drops connections without an HTTP response to simulate a transport failure", testCase.name)
	}
	h.Logger.Infof("[%s] Expected detector unavailable=%t, classifier score >= %d: %t", testCase.name, expected.unavailable, expected.threshold, expected.above)
	return nil
}

func checkClassifierParallelTiming(batch, single time.Duration) error {
	if single <= 0 || batch >= 2*single {
		return fmt.Errorf("five-message classification must finish in under twice one-call time (batch_ms=%.1f single_ms=%.1f limit_ms=%.1f); start calls in parallel instead of waiting after each message", float64(batch)/float64(time.Millisecond), float64(single)/float64(time.Millisecond), float64(2*single)/float64(time.Millisecond))
	}
	return nil
}

func checkClassifierDeadline(elapsed time.Duration) error {
	if elapsed >= 600*time.Millisecond {
		return fmt.Errorf("classifier call exceeded timeout budget: elapsed_ms=%.1f limit_ms=600.0; enforce a 200ms whole-call deadline, including response body reads", float64(elapsed)/float64(time.Millisecond))
	}
	return nil
}

func (fixture *classifierFixture) check(h *test_case_harness.TestCaseHarness, testCase policyCase, headers http.Header, elapsed time.Duration) error {
	expected := *testCase.classifier
	if expected.timing == "single" {
		fixture.singleLatency = elapsed
	}
	if expected.timing == "batch" {
		h.Logger.Infof("[%s] Classifier parallel timing: batch_ms=%.1f single_ms=%.1f limit_ms=%.1f", testCase.name, float64(elapsed)/float64(time.Millisecond), float64(fixture.singleLatency)/float64(time.Millisecond), float64(2*fixture.singleLatency)/float64(time.Millisecond))
		if err := checkClassifierParallelTiming(elapsed, fixture.singleLatency); err != nil {
			return err
		}
	}
	if expected.deadline {
		h.Logger.Infof("[%s] Classifier timeout timing: elapsed_ms=%.1f limit_ms=600.0 (200ms deadline plus scheduling headroom)", testCase.name, float64(elapsed)/float64(time.Millisecond))
		if err := checkClassifierDeadline(elapsed); err != nil {
			return err
		}
	}
	fixture.lock.Lock()
	requests := append([]classifierRequest(nil), fixture.requests[fixture.offset:]...)
	fixture.lock.Unlock()
	messages := fixture.expected
	if fixture.down {
		messages = nil
	}
	if err := checkClassifierRequests(requests, messages); err != nil {
		return err
	}
	if err := checkClassifierHeaders(headers, expected); err != nil {
		return err
	}
	h.Logger.Successf("[%s] Original messages classified exactly once; detector availability and score category match", testCase.name)
	return nil
}
