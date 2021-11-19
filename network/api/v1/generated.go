// Package v1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.8.2 DO NOT EDIT.
package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
)

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
	// ListTransactions request
	ListTransactions(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetTransaction request
	GetTransaction(ctx context.Context, ref string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetTransactionPayload request
	GetTransactionPayload(ctx context.Context, ref string, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) ListTransactions(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewListTransactionsRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetTransaction(ctx context.Context, ref string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetTransactionRequest(c.Server, ref)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetTransactionPayload(ctx context.Context, ref string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetTransactionPayloadRequest(c.Server, ref)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewListTransactionsRequest generates requests for ListTransactions
func NewListTransactionsRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/network/v1/transaction")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetTransactionRequest generates requests for GetTransaction
func NewGetTransactionRequest(server string, ref string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "ref", runtime.ParamLocationPath, ref)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/network/v1/transaction/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetTransactionPayloadRequest generates requests for GetTransactionPayload
func NewGetTransactionPayloadRequest(server string, ref string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "ref", runtime.ParamLocationPath, ref)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/internal/network/v1/transaction/%s/payload", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

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
	// ListTransactions request
	ListTransactionsWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*ListTransactionsResponse, error)

	// GetTransaction request
	GetTransactionWithResponse(ctx context.Context, ref string, reqEditors ...RequestEditorFn) (*GetTransactionResponse, error)

	// GetTransactionPayload request
	GetTransactionPayloadWithResponse(ctx context.Context, ref string, reqEditors ...RequestEditorFn) (*GetTransactionPayloadResponse, error)
}

type ListTransactionsResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *[]string
}

// Status returns HTTPResponse.Status
func (r ListTransactionsResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r ListTransactionsResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetTransactionResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r GetTransactionResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetTransactionResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetTransactionPayloadResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r GetTransactionPayloadResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetTransactionPayloadResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// ListTransactionsWithResponse request returning *ListTransactionsResponse
func (c *ClientWithResponses) ListTransactionsWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*ListTransactionsResponse, error) {
	rsp, err := c.ListTransactions(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseListTransactionsResponse(rsp)
}

// GetTransactionWithResponse request returning *GetTransactionResponse
func (c *ClientWithResponses) GetTransactionWithResponse(ctx context.Context, ref string, reqEditors ...RequestEditorFn) (*GetTransactionResponse, error) {
	rsp, err := c.GetTransaction(ctx, ref, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetTransactionResponse(rsp)
}

// GetTransactionPayloadWithResponse request returning *GetTransactionPayloadResponse
func (c *ClientWithResponses) GetTransactionPayloadWithResponse(ctx context.Context, ref string, reqEditors ...RequestEditorFn) (*GetTransactionPayloadResponse, error) {
	rsp, err := c.GetTransactionPayload(ctx, ref, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetTransactionPayloadResponse(rsp)
}

// ParseListTransactionsResponse parses an HTTP response from a ListTransactionsWithResponse call
func ParseListTransactionsResponse(rsp *http.Response) (*ListTransactionsResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &ListTransactionsResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest []string
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseGetTransactionResponse parses an HTTP response from a GetTransactionWithResponse call
func ParseGetTransactionResponse(rsp *http.Response) (*GetTransactionResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &GetTransactionResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParseGetTransactionPayloadResponse parses an HTTP response from a GetTransactionPayloadWithResponse call
func ParseGetTransactionPayloadResponse(rsp *http.Response) (*GetTransactionPayloadResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &GetTransactionPayloadResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Lists the transactions on the DAG
	// (GET /internal/network/v1/transaction)
	ListTransactions(ctx echo.Context) error
	// Retrieves a transaction
	// (GET /internal/network/v1/transaction/{ref})
	GetTransaction(ctx echo.Context, ref string) error
	// Gets the transaction payload
	// (GET /internal/network/v1/transaction/{ref}/payload)
	GetTransactionPayload(ctx echo.Context, ref string) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// ListTransactions converts echo context to params.
func (w *ServerInterfaceWrapper) ListTransactions(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.ListTransactions(ctx)
	return err
}

// GetTransaction converts echo context to params.
func (w *ServerInterfaceWrapper) GetTransaction(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "ref" -------------
	var ref string

	err = runtime.BindStyledParameterWithLocation("simple", false, "ref", runtime.ParamLocationPath, ctx.Param("ref"), &ref)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter ref: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetTransaction(ctx, ref)
	return err
}

// GetTransactionPayload converts echo context to params.
func (w *ServerInterfaceWrapper) GetTransactionPayload(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "ref" -------------
	var ref string

	err = runtime.BindStyledParameterWithLocation("simple", false, "ref", runtime.ParamLocationPath, ctx.Param("ref"), &ref)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter ref: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.GetTransactionPayload(ctx, ref)
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
	router.Add(http.MethodGet, baseURL+"/internal/network/v1/transaction", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("ListTransactions", context)
		return wrapper.ListTransactions(context)
	})
	router.Add(http.MethodGet, baseURL+"/internal/network/v1/transaction/:ref", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("GetTransaction", context)
		return wrapper.GetTransaction(context)
	})
	router.Add(http.MethodGet, baseURL+"/internal/network/v1/transaction/:ref/payload", func(context echo.Context) error {
		si.(Preprocessor).Preprocess("GetTransactionPayload", context)
		return wrapper.GetTransactionPayload(context)
	})

}