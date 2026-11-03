package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bjdgyc/anylink/base"
	"github.com/gorilla/mux"
)

func testSSOAdminRouter(t *testing.T) (*mux.Router, string) {
	t.Helper()
	previous := *base.Cfg
	base.Cfg.AdminUser = "sso-test-admin"
	base.Cfg.JwtSecret = "test-only-jwt-key"
	t.Cleanup(func() { *base.Cfg = previous })
	token, err := SetJwtData(map[string]interface{}{"admin_user": base.Cfg.AdminUser}, time.Now().Add(time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	router := mux.NewRouter()
	router.Use(authMiddleware)
	registerGroupSSORoutes(router)
	return router, token
}

func TestGroupSSORoutesRequireAdminAndCorrectMethod(t *testing.T) {
	router, token := testSSOAdminRouter(t)
	for _, endpoint := range []struct{ method, path string }{{"GET", "/group/sso?id=1"}, {"POST", "/group/sso/set"}} {
		request := httptest.NewRequest(endpoint.method, endpoint.path, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s returned %d", endpoint.path, response.Code)
		}
	}
	for _, endpoint := range []struct{ method, path string }{{"POST", "/group/sso"}, {"GET", "/group/sso/set"}} {
		request := httptest.NewRequest(endpoint.method, endpoint.path, nil)
		request.Header.Set("Jwt", token)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("wrong method %s returned %d", endpoint.path, response.Code)
		}
	}
	request := httptest.NewRequest("GET", "/group/sso?id=invalid", nil)
	request.Header.Set("Jwt", token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	var result Resp
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Code != RespParamErr || result.Msg != "sso_group_id_invalid" {
		t.Fatalf("authenticated handler result: %s, %v", response.Body, err)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("SSO response is cacheable")
	}
}

func TestGroupSSOSetRejectsMalformedAndAmbiguousRequests(t *testing.T) {
	router, token := testSSOAdminRouter(t)
	cases := []struct{ name, contentType, body, message string }{
		{"form", "application/x-www-form-urlencoded", "id=1", "sso_content_type_required"},
		{"plain JSON", "text/plain", `{}`, "sso_content_type_required"},
		{"bad JSON", "application/json", `{`, "sso_request_invalid"},
		{"extra request", "application/json", `{} {}`, "sso_request_invalid"},
		{"unexpected top-level field", "application/json", `{"auth":{}}`, "sso_request_invalid"},
		{"unexpected config field", "application/json", `{"config":{"password":"private"}}`, "sso_request_invalid"},
		{"oversized", "application/json", `{"revision":"` + strings.Repeat("x", 128<<10) + `"}`, "sso_request_invalid"},
		{"valid JSON invalid id", "application/json; charset=utf-8", `{"id":0,"config":{},"revision":"x","secret_action":"preserve"}`, "sso_group_id_invalid"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/group/sso/set", strings.NewReader(test.body))
			request.Header.Set("Jwt", token)
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			var result Resp
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Code != RespParamErr || result.Msg != test.message {
				t.Fatalf("unexpected result: %s, %v", response.Body, err)
			}
			if strings.Contains(response.Body.String(), "private") {
				t.Fatal("request secret leaked in error")
			}
		})
	}
}
