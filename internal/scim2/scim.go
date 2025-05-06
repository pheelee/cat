package scim2

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/elimity-com/scim"
	"github.com/elimity-com/scim/optional"
	"github.com/elimity-com/scim/schema"
)

type SCIMInstance struct {
	server *scim.Server
	log    []message
}

func (s *SCIMInstance) Logs() []message {
	return s.log
}

type message struct {
	http.ResponseWriter `json:"-"`
	Timestamp           time.Time `json:"timestamp"`
	Method              string    `json:"method"`
	URL                 string    `json:"url"`
	StatusCode          int       `json:"status_code"`
	Headers             []string  `json:"headers"`
	Request             string    `json:"request"`
	Response            string    `json:"response"`
}

type resourceData struct {
	attributes scim.ResourceAttributes
	meta       scim.Meta
}

func (m *message) WriteHeader(statusCode int) {
	m.StatusCode = statusCode
	m.ResponseWriter.WriteHeader(statusCode)
}

func (m *message) Write(b []byte) (int, error) {
	m.Response = string(b)
	return m.ResponseWriter.Write(b)
}

type logger struct{}

func (logger) Error(args ...interface{}) {
	fmt.Println("SCIM Logger:", args)
}

func GetServer(endpoint string) (*SCIMInstance, error) {
	config := scim.ServiceProviderConfig{
		DocumentationURI: optional.NewString(endpoint),
	}

	resourceTypes := []scim.ResourceType{
		{
			ID:          optional.NewString("User"),
			Name:        "User",
			Endpoint:    "/Users",
			Description: optional.NewString("User Account"),
			Schema:      schema.CoreUserSchema(),
			SchemaExtensions: []scim.SchemaExtension{
				{Schema: schema.ExtensionEnterpriseUser()},
			},
			Handler: &memoryResourceHandler{
				data:   make(map[string]resourceData),
				schema: schema.CoreUserSchema(),
				nextID: 1,
			},
		},
		{
			ID:               optional.NewString("Group"),
			Name:             "Group",
			Endpoint:         "/Groups",
			Description:      optional.NewString("Group"),
			Schema:           schema.CoreGroupSchema(),
			SchemaExtensions: []scim.SchemaExtension{},
			Handler: &memoryResourceHandler{
				data:   make(map[string]resourceData),
				schema: schema.CoreGroupSchema(),
				nextID: 1,
			},
		},
	}

	opts := []scim.ServerOption{
		scim.WithLogger(logger{}),
	}
	srv, err := scim.NewServer(&scim.ServerArgs{
		ServiceProviderConfig: &config,
		ResourceTypes:         resourceTypes,
	}, opts...)

	if err != nil {
		return nil, err
	}
	return &SCIMInstance{
		server: &srv,
		log:    []message{},
	}, nil
}

func (s *SCIMInstance) SCIMRecorder() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			// Log Error!
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		rec := message{
			Timestamp:  time.Now().UTC(),
			Method:     r.Method,
			URL:        r.URL.String(),
			StatusCode: http.StatusOK,
			Request:    string(body),
		}
		// Put all headers in an array
		for k, v := range r.Header {
			rec.Headers = append(rec.Headers, k+": "+v[0])
		}
		rec.ResponseWriter = w
		s.server.ServeHTTP(&rec, r)
		s.log = append(s.log, rec)
	})
}
