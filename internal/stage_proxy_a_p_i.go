package internal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/codecrafters-io/tester-utils/test_case_harness"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

type proxyCase struct {
	name        string
	params      openai.ChatCompletionNewParams
	status      int
	body        string
	content     string
	unavailable bool
}

type originRequest struct {
	method        string
	path          string
	host          string
	authorization string
	contentType   string
	body          []byte
	readError     error
}

func testProxyAPI(harness *test_case_harness.TestCaseHarness) error {
	minimal := openai.ChatCompletionNewParams{
		Model:    "course-model",
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Say hello.")},
	}
	cases := []proxyCase{
		{
			name: "sdk-completion", params: minimal, status: http.StatusOK, content: "Hello.",
			body: `{"id":"chatcmpl-course-1","object":"chat.completion","created":1700000000,"model":"course-model","choices":[{"index":0,"message":{"role":"assistant","content":"Hello."},"finish_reason":"stop"}]}`,
		},
		{
			name: "conversation-and-optional-fields", status: http.StatusOK, content: "caf\u00e9\nReady!",
			params: openai.ChatCompletionNewParams{
				Model: "course-model",
				Messages: []openai.ChatCompletionMessageParamUnion{
					openai.SystemMessage("Keep the conversation intact."),
					openai.UserMessage("Remember caf\u00e9."),
					openai.AssistantMessage("Remembered."),
					openai.UserMessage("Repeat it, then say \"Ready!\" on a new line."),
				},
				Temperature: openai.Float(0.25),
			},
			body: `{"id":"chatcmpl-course-2","object":"chat.completion","created":1700000001,"model":"course-model","choices":[{"index":0,"message":{"role":"assistant","content":"caf\u00e9\nReady!"},"finish_reason":"stop"}],"course_marker":"preserve-this-field"}`,
		},
		{
			name: "origin-http-error", params: minimal, status: http.StatusBadRequest,
			body: `{"error":{"message":"Scripted invalid request","type":"invalid_request_error","param":"model","code":"course_error"}}`,
		},
		{name: "origin-unavailable", params: minimal, status: http.StatusBadGateway, unavailable: true},
	}

	requests := make(chan originRequest, 8)
	var replyLock sync.RWMutex
	var reply proxyCase
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		select {
		case requests <- originRequest{r.Method, r.URL.Path, r.Host, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), body, err}:
		default:
		}
		replyLock.RLock()
		current := reply
		replyLock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-"+current.name)
		if current.status == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(current.status)
		io.WriteString(w, current.body)
	}))
	origin.Config.ReadTimeout = 3 * time.Second
	origin.Config.WriteTimeout = 3 * time.Second
	origin.Start()
	process, err := startFirewall(harness, origin.URL, "cloudflare-stage-2-", 25*time.Second, "{}\n")
	if err != nil {
		origin.Close()
		return err
	}
	// Stop the learner before closing the origin, including after a bad request.
	harness.RegisterTeardownFunc(origin.Close)
	if err := checkFirewallHealth(harness, process); err != nil {
		return err
	}

	httpClient := firewallHTTPClient(3 * time.Second)
	defer httpClient.CloseIdleConnections()
	client := openai.NewClient(
		option.WithAPIKey("course-test-key"),
		option.WithBaseURL("http://127.0.0.1:8080/v1"),
		option.WithMaxRetries(0),
		option.WithHTTPClient(httpClient),
	)
	for _, testCase := range cases {
		if testCase.unavailable {
			origin.Close()
			harness.Logger.Infof("[%s] Stopped the mock origin", testCase.name)
		} else {
			replyLock.Lock()
			reply = testCase
			replyLock.Unlock()
			harness.Logger.Infof("[%s] Origin response: HTTP %d, Content-Type: application/json, X-Request-Id: req-%s", testCase.name, testCase.status, testCase.name)
			harness.Logger.Infof("[%s] Origin body: %s", testCase.name, testCase.body)
		}
		expectedBody, err := testCase.params.MarshalJSON()
		if err != nil {
			return err
		}
		harness.Logger.Infof("[%s] SDK POST /v1/chat/completions, Authorization: Bearer course-test-key, Content-Type: application/json", testCase.name)
		harness.Logger.Infof("[%s] Request body: %s", testCase.name, expectedBody)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var response *http.Response
		var rawBody []byte
		completion, callError := client.Chat.Completions.New(ctx, testCase.params, option.WithResponseInto(&response), captureResponseBody(&rawBody))
		cancel()
		if response == nil {
			if errors.Is(callError, context.DeadlineExceeded) {
				return fmt.Errorf("%s: no HTTP response from the firewall within 3s; relay the origin response or return HTTP 502 on connection failure", testCase.name)
			}
			return fmt.Errorf("%s: expected HTTP %d, but the SDK received no HTTP response: %v", testCase.name, testCase.status, callError)
		}

		if !testCase.unavailable {
			select {
			case request := <-requests:
				if request.readError != nil {
					return fmt.Errorf("%s: could not read the request forwarded to the origin: %w", testCase.name, request.readError)
				}
				if request.method != http.MethodPost || request.path != "/v1/chat/completions" {
					return fmt.Errorf("%s: expected origin request POST /v1/chat/completions, got %s %s", testCase.name, request.method, request.path)
				}
				if request.host != origin.Listener.Addr().String() {
					return fmt.Errorf("%s: origin request Host is %q; set it to the host from --origin", testCase.name, request.host)
				}
				if request.authorization != "Bearer course-test-key" || request.contentType != "application/json" {
					return fmt.Errorf("%s: forward Authorization and Content-Type unchanged; got Authorization=%q, Content-Type=%q", testCase.name, request.authorization, request.contentType)
				}
				if !bytes.Equal(request.body, expectedBody) {
					return fmt.Errorf("%s: origin request body changed; expected %+q, got %+q", testCase.name, expectedBody, request.body)
				}
			default:
				return fmt.Errorf("%s: the origin did not receive the API request; forward it to --origin", testCase.name)
			}
		}
		if response.StatusCode != testCase.status {
			return fmt.Errorf("%s: expected HTTP %d, got HTTP %d", testCase.name, testCase.status, response.StatusCode)
		}
		if testCase.unavailable {
			response.Body.Close()
			harness.Logger.Successf("[%s] Received HTTP 502 when the origin was unavailable", testCase.name)
			continue
		}
		if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("X-Request-Id") != "req-"+testCase.name {
			return fmt.Errorf("%s: relay the origin's Content-Type and X-Request-Id headers unchanged", testCase.name)
		}
		var actualBody string
		if testCase.status == http.StatusOK {
			if callError != nil {
				return fmt.Errorf("%s: the SDK could not read the relayed completion: %w", testCase.name, callError)
			}
			actualBody = string(rawBody)
			if len(completion.Choices) != 1 || completion.Choices[0].Message.Content != testCase.content {
				return fmt.Errorf("%s: the SDK did not receive the scripted assistant message", testCase.name)
			}
		} else {
			var apiError *openai.Error
			if !errors.As(callError, &apiError) {
				return fmt.Errorf("%s: the SDK could not read the origin's API error: %v", testCase.name, callError)
			}
			// The SDK unwraps the error object but restores the full wire body.
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				return fmt.Errorf("%s: could not read the relayed error body: %w", testCase.name, err)
			}
			actualBody = string(body)
		}
		if actualBody != testCase.body {
			return fmt.Errorf("%s: origin response body changed; expected %+q, got %+q", testCase.name, testCase.body, actualBody)
		}
		harness.Logger.Successf("[%s] SDK received the origin's response unchanged", testCase.name)
	}
	return nil
}

// Capture wire bytes before the SDK decodes JSON, which permits trailing data.
func captureResponseBody(destination *[]byte) option.RequestOption {
	return option.WithMiddleware(func(request *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		response, err := next(request)
		if err != nil {
			return response, err
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return nil, err
		}
		*destination = body
		response.Body = io.NopCloser(bytes.NewReader(body))
		return response, nil
	})
}
