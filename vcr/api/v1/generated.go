// Package v1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.8.2 DO NOT EDIT.
package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
)

// Defines values for ResolutionResultCurrentStatus.
const (
	ResolutionResultCurrentStatusRevoked ResolutionResultCurrentStatus = "revoked"

	ResolutionResultCurrentStatusTrusted ResolutionResultCurrentStatus = "trusted"

	ResolutionResultCurrentStatusUntrusted ResolutionResultCurrentStatus = "untrusted"
)

// CredentialIssuer defines model for CredentialIssuer.
type CredentialIssuer struct {
	// a credential type
	CredentialType string `json:"credentialType"`

	// the DID of an issuer
	Issuer string `json:"issuer"`
}

// DID according to specification
type DID string

// Json schema.
type JsonSchema map[string]interface{}

// result of a Resolve operation.
type ResolutionResult struct {
	// Only credentials with with "trusted" state are valid. If a revoked credential is also untrusted, revoked will be returned.
	CurrentStatus ResolutionResultCurrentStatus `json:"currentStatus"`

	// A credential according to the W3C and Nuts specs.
	VerifiableCredential VerifiableCredential `json:"verifiableCredential"`
}

// Only credentials with with "trusted" state are valid. If a revoked credential is also untrusted, revoked will be returned.
type ResolutionResultCurrentStatus string

// A request for issuing a new Verifiable Credential.
type ResolveVCRequest struct {
	// Credential type.
	CredentialType string `json:"credentialType"`

	// URL encoded ID.
	Id string `json:"id"`

	// a rfc3339 time string for resolving a VC at a specific moment in time.
	ResolveTime *string `json:"resolveTime,omitempty"`
}

// A request for issuing a revoke Verifiable Credential.
type RevokeVCRequest struct {
	// Credential type.
	CredentialType string `json:"credentialType"`

	// URL encoded ID.
	Id string `json:"id"`
}

// CreateJSONBody defines parameters for Create.
type CreateJSONBody CreateSchemaRequest

// IssueJSONBody defines parameters for Issue.
type IssueJSONBody IssueVCRequest

// ResolveJSONBody defines parameters for Resolve.
type ResolveJSONBody ResolveVCRequest

// RevokeJSONBody defines parameters for Revoke.
type RevokeJSONBody RevokeVCRequest

// CreateJSONRequestBody defines body for Create for application/json ContentType.
type CreateJSONRequestBody CreateJSONBody

// IssueJSONRequestBody defines body for Issue for application/json ContentType.
type IssueJSONRequestBody IssueJSONBody

// ResolveJSONRequestBody defines body for Resolve for application/json ContentType.
type ResolveJSONRequestBody ResolveJSONBody

// RevokeJSONRequestBody defines body for Revoke for application/json ContentType.
type RevokeJSONRequestBody RevokeJSONBody

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// Create request with any body
	CreateWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	Create(ctx context.Context, body CreateJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// Issue request with any body
	IssueWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	Issue(ctx context.Context, body IssueJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// Resolve request with any body
	ResolveWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	Resolve(ctx context.Context, body ResolveJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// Revoke request with any body
	RevokeWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	Revoke(ctx context.Context, body RevokeJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) CreateWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewCreateRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) Create(ctx context.Context, body CreateJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewCreateRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) IssueWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewIssueRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) Issue(ctx context.Context, body IssueJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewIssueRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) ResolveWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewResolveRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) Resolve(ctx context.Context, body ResolveJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewResolveRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) RevokeWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewRevokeRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) Revoke(ctx context.Context, body RevokeJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewRevokeRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewCreateRequest calls the generic Create builder with application/json body
func NewCreateRequest(server string, body CreateJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewCreateRequestWithBody(server, "application/json", bodyReader)
}

// NewCreateRequestWithBody generates requests for Create with any type of body
func NewCreateRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/vcr/v1/schema")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewIssueRequest calls the generic Issue builder with application/json body
func NewIssueRequest(server string, body IssueJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewIssueRequestWithBody(server, "application/json", bodyReader)
}

// NewIssueRequestWithBody generates requests for Issue with any type of body
func NewIssueRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/vcr/v1/vc/new")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewResolveRequest calls the generic Resolve builder with application/json body
func NewResolveRequest(server string, body ResolveJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewResolveRequestWithBody(server, "application/json", bodyReader)
}

// NewResolveRequestWithBody generates requests for Resolve with any type of body
func NewResolveRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/vcr/v1/vc/read")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewRevokeRequest calls the generic Revoke builder with application/json body
func NewRevokeRequest(server string, body RevokeJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewRevokeRequestWithBody(server, "application/json", bodyReader)
}

// NewRevokeRequestWithBody generates requests for Revoke with any type of body
func NewRevokeRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/vcr/v1/vc/revoke")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// Create request with any body
	CreateWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CreateResponse, error)

	CreateWithResponse(ctx context.Context, body CreateJSONRequestBody, reqEditors ...RequestEditorFn) (*CreateResponse, error)

	// Issue request with any body
	IssueWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*IssueResponse, error)

	IssueWithResponse(ctx context.Context, body IssueJSONRequestBody, reqEditors ...RequestEditorFn) (*IssueResponse, error)

	// Resolve request with any body
	ResolveWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*ResolveResponse, error)

	ResolveWithResponse(ctx context.Context, body ResolveJSONRequestBody, reqEditors ...RequestEditorFn) (*ResolveResponse, error)

	// Revoke request with any body
	RevokeWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*RevokeResponse, error)

	RevokeWithResponse(ctx context.Context, body RevokeJSONRequestBody, reqEditors ...RequestEditorFn) (*RevokeResponse, error)
}

type CreateResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r CreateResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r CreateResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type IssueResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r IssueResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r IssueResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type ResolveResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r ResolveResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ResolveResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type RevokeResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r RevokeResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r RevokeResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// CreateWithBodyWithResponse request with arbitrary body returning *CreateResponse
func (c *ClientWithResponses) CreateWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CreateResponse, error) {
	rsp, err := c.CreateWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCreateResponse(rsp)
}

func (c *ClientWithResponses) CreateWithResponse(ctx context.Context, body CreateJSONRequestBody, reqEditors ...RequestEditorFn) (*CreateResponse, error) {
	rsp, err := c.Create(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseCreateResponse(rsp)
}

// IssueWithBodyWithResponse request with arbitrary body returning *IssueResponse
func (c *ClientWithResponses) IssueWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*IssueResponse, error) {
	rsp, err := c.IssueWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseIssueResponse(rsp)
}

func (c *ClientWithResponses) IssueWithResponse(ctx context.Context, body IssueJSONRequestBody, reqEditors ...RequestEditorFn) (*IssueResponse, error) {
	rsp, err := c.Issue(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseIssueResponse(rsp)
}

// ResolveWithBodyWithResponse request with arbitrary body returning *ResolveResponse
func (c *ClientWithResponses) ResolveWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*ResolveResponse, error) {
	rsp, err := c.ResolveWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseResolveResponse(rsp)
}

func (c *ClientWithResponses) ResolveWithResponse(ctx context.Context, body ResolveJSONRequestBody, reqEditors ...RequestEditorFn) (*ResolveResponse, error) {
	rsp, err := c.Resolve(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseResolveResponse(rsp)
}

// RevokeWithBodyWithResponse request with arbitrary body returning *RevokeResponse
func (c *ClientWithResponses) RevokeWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*RevokeResponse, error) {
	rsp, err := c.RevokeWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseRevokeResponse(rsp)
}

func (c *ClientWithResponses) RevokeWithResponse(ctx context.Context, body RevokeJSONRequestBody, reqEditors ...RequestEditorFn) (*RevokeResponse, error) {
	rsp, err := c.Revoke(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseRevokeResponse(rsp)
}

// ParseCreateResponse parses an HTTP response from a CreateWithResponse call
func ParseCreateResponse(rsp *http.Response) (*CreateResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &CreateResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseIssueResponse parses an HTTP response from a IssueWithResponse call
func ParseIssueResponse(rsp *http.Response) (*IssueResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &IssueResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseResolveResponse parses an HTTP response from a ResolveWithResponse call
func ParseResolveResponse(rsp *http.Response) (*ResolveResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &ResolveResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseRevokeResponse parses an HTTP response from a RevokeWithResponse call
func ParseRevokeResponse(rsp *http.Response) (*RevokeResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &RevokeResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Creates a new Verifiable Credential Schema
	// (POST /internal/vcr/v1/schema)
	Create(ctx echo.Context) error
	// Issue a new Verifiable Credential
	// (POST /internal/vcr/v1/vc/new)
	Issue(ctx echo.Context) error
	// Resolves a verifiable credential
	// (POST /internal/vcr/v1/vc/read)
	Resolve(ctx echo.Context) error
	// Revoke a credential
	// (POST /internal/vcr/v1/vc/revoke)
	Revoke(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// Create converts echo context to params.
func (w *ServerInterfaceWrapper) Create(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Create(ctx)
	return err
}

// Issue converts echo context to params.
func (w *ServerInterfaceWrapper) Issue(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Issue(ctx)
	return err
}

// Resolve converts echo context to params.
func (w *ServerInterfaceWrapper) Resolve(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Resolve(ctx)
	return err
}

// Revoke converts echo context to params.
func (w *ServerInterfaceWrapper) Revoke(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.Revoke(ctx)
	return err
}

// PATCH: This template file was taken from pkg/codegen/templates/register.tmpl

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	Add(method string, path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

type Preprocessor interface {
	Preprocess(operationID string, context echo.Context)
}

type ErrorStatusCodeResolver interface {
	ResolveStatusCode(err error) int
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface) {
	RegisterHandlersWithBaseURL(router, si, "")
}

// Registers handlers, and prepends BaseURL to the paths, so that the paths
// can be served under a prefix.
func RegisterHandlersWithBaseURL(router EchoRouter, si ServerInterface, baseURL string) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	// PATCH: This alteration wraps the call to the implementation in a function that sets the "OperationId" context parameter,
	// so it can be used in error reporting middleware.
	router.Add(http.MethodPost, baseURL+"/internal/vcr/v1/schema", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("Create", context)
		return wrapper.Create(context)
	})
	router.Add(http.MethodPost, baseURL+"/internal/vcr/v1/vc/new", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("Issue", context)
		return wrapper.Issue(context)
	})
	router.Add(http.MethodPost, baseURL+"/internal/vcr/v1/vc/read", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("Resolve", context)
		return wrapper.Resolve(context)
	})
	router.Add(http.MethodPost, baseURL+"/internal/vcr/v1/vc/revoke", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("Revoke", context)
		return wrapper.Revoke(context)
	})

}
