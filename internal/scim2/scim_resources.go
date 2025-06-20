package scim2

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/elimity-com/scim"
	"github.com/elimity-com/scim/errors"
	internal "github.com/elimity-com/scim/filter"
	"github.com/elimity-com/scim/optional"
	"github.com/elimity-com/scim/schema"
	"github.com/scim2/filter-parser/v2"
)

type memoryResourceHandler struct {
	sync.Mutex
	nextID int
	data   map[string]resourceData
	schema schema.Schema
}

func checkBodyNotEmpty(r *http.Request) error {
	// Check whether the request body is empty.
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("passed body is empty")
	}
	return nil
}

// externalID extracts the external identifier of the given attributes.
func externalID(attributes scim.ResourceAttributes) optional.String {
	if eID, ok := attributes["externalId"]; ok {
		if externalID, ok := eID.(string); ok {
			return optional.NewString(externalID)
		}
	}
	return optional.String{}
}

func (h *memoryResourceHandler) Create(r *http.Request, attributes scim.ResourceAttributes) (scim.Resource, error) {
	h.Lock()
	defer h.Unlock()
	if err := checkBodyNotEmpty(r); err != nil {
		return scim.Resource{}, err
	}

	var (
		id   = h.createID()
		now  = time.Now()
		meta = scim.Meta{
			Created:      &now,
			LastModified: &now,
			Version:      fmt.Sprintf("v%d", now.Unix()),
		}
	)
	h.data[id] = resourceData{
		attributes: attributes,
		meta:       meta,
	}
	return scim.Resource{
		ID:         id,
		ExternalID: externalID(attributes),
		Attributes: attributes,
		Meta:       meta,
	}, nil
}

func (h *memoryResourceHandler) Delete(r *http.Request, id string) error {
	h.Lock()
	defer h.Unlock()
	if _, ok := h.data[id]; !ok {
		return errors.ScimErrorResourceNotFound(id)
	}
	delete(h.data, id)
	return nil
}

func (h *memoryResourceHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	h.Lock()
	defer h.Unlock()
	resource, ok := h.data[id]
	if !ok {
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}
	return scim.Resource{
		ID:         id,
		ExternalID: externalID(resource.attributes),
		Attributes: resource.attributes,
		Meta:       resource.meta,
	}, nil
}

func (h *memoryResourceHandler) GetAll(r *http.Request, params scim.ListRequestParams) (scim.Page, error) {
	h.Lock()
	defer h.Unlock()
	if params.Count == 0 {
		return scim.Page{
			TotalResults: len(h.data),
		}, nil
	}
	var (
		resources = []scim.Resource{}
		index     int
	)
	for k, v := range h.data {
		index++ // 1-indexed
		if index < params.StartIndex {
			continue
		}
		if len(resources) == params.Count {
			break
		}

		validator := internal.NewFilterValidator(params.FilterValidator.GetFilter(), h.schema)
		if err := validator.PassesFilter(v.attributes); err != nil {
			continue
		}

		resources = append(resources, scim.Resource{
			ID:         k,
			ExternalID: externalID(v.attributes),
			Attributes: v.attributes,
			Meta:       v.meta,
		})
	}
	return scim.Page{
		TotalResults: len(h.data),
		Resources:    resources,
	}, nil
}

func (h *memoryResourceHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	h.Lock()
	defer h.Unlock()
	if err := checkBodyNotEmpty(r); err != nil {
		return scim.Resource{}, err
	}

	if _, ok := h.data[id]; !ok {
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}
	var changed bool // Whether or not changes where made
	for _, op := range operations {
		// Target is the root node.
		if op.Path == nil {
			for k, v := range op.Value.(map[string]interface{}) {
				if v == nil {
					continue
				}

				path, _ := filter.ParseAttrPath([]byte(k))
				if subAttrName := path.SubAttributeName(); subAttrName != "" {
					if old, ok := h.data[id].attributes[path.AttributeName]; ok {
						m := old.(map[string]interface{})
						if sub, ok := m[subAttrName]; ok {
							if sub == v {
								continue
							}
						}
						changed = true
						m[subAttrName] = v
						h.data[id].attributes[path.AttributeName] = m
						continue
					}
					changed = true
					h.data[id].attributes[path.AttributeName] = map[string]interface{}{
						subAttrName: v,
					}
					continue
				}
				old, ok := h.data[id].attributes[k]
				if !ok {
					changed = true
					h.data[id].attributes[k] = v
					continue
				}
				switch v := v.(type) {
				case []interface{}:
					changed = true
					h.data[id].attributes[k] = append(old.([]interface{}), v...)
				case map[string]interface{}:
					m := old.(map[string]interface{})
					var changed_ bool
					for attr, value := range v {
						if value == nil {
							continue
						}

						if v, ok := m[attr]; ok {
							if v == nil || v == value {
								continue
							}
						}
						changed = true
						changed_ = true
						m[attr] = value
					}
					if changed_ {
						h.data[id].attributes[k] = m
					}
				default:
					if old == v {
						continue
					}
					changed = true
					h.data[id].attributes[k] = v // replace
				}
			}
			continue
		}

		var (
			attrName    = op.Path.AttributePath.AttributeName
			subAttrName = op.Path.AttributePath.SubAttributeName()
			valueExpr   = op.Path.ValueExpression
		)

		// Attribute does not exist yet.
		old, ok := h.data[id].attributes[attrName]
		if !ok {
			switch {
			case subAttrName != "":
				changed = true
				h.data[id].attributes[attrName] = map[string]interface{}{
					subAttrName: op.Value,
				}
			case valueExpr != nil:
				// Do nothing since there is nothing to match the filter?
			default:
				changed = true
				h.data[id].attributes[attrName] = op.Value
			}
			continue
		}

		switch op.Op {
		case "add":
			switch v := op.Value.(type) {
			case []interface{}:
				changed = true
				h.data[id].attributes[attrName] = append(old.([]interface{}), v...)
			default:
				if subAttrName != "" {
					m := old.(map[string]interface{})
					if value, ok := old.(map[string]interface{})[subAttrName]; ok {
						if v == value {
							continue
						}
					}
					changed = true
					m[subAttrName] = v
					h.data[id].attributes[attrName] = m
					continue
				}
				switch v := v.(type) {
				case map[string]interface{}:
					m := old.(map[string]interface{})
					var changed_ bool
					for attr, value := range v {
						if value == nil {
							continue
						}

						if v, ok := m[attr]; ok {
							if v == nil || v == value {
								continue
							}
						}
						changed = true
						changed_ = true
						m[attr] = value
					}
					if changed_ {
						h.data[id].attributes[attrName] = m
					}
				default:
					if old == v {
						continue
					}
					changed = true
					h.data[id].attributes[attrName] = v // replace
				}
			}
		}
	}

	if !changed {
		// StatusNoContent
		return scim.Resource{}, nil
	}

	resource := h.data[id]
	return scim.Resource{
		ID:         id,
		ExternalID: externalID(resource.attributes),
		Attributes: resource.attributes,
		Meta:       resource.meta,
	}, nil
}

func (h *memoryResourceHandler) Replace(r *http.Request, id string, attributes scim.ResourceAttributes) (scim.Resource, error) {
	h.Lock()
	defer h.Unlock()
	if err := checkBodyNotEmpty(r); err != nil {
		return scim.Resource{}, err
	}
	resource, ok := h.data[id]
	if !ok {
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}
	var (
		now  = time.Now()
		meta = scim.Meta{
			Created:      resource.meta.Created,
			LastModified: &now,
			Version:      fmt.Sprintf("v%d", now.Unix()),
		}
	)
	h.data[id] = resourceData{
		attributes: attributes,
		meta:       meta,
	}
	return scim.Resource{
		ID:         id,
		ExternalID: externalID(attributes),
		Attributes: attributes,
		Meta:       meta,
	}, nil
}

// createID returns a unique identifier for a resource.
func (h *memoryResourceHandler) createID() string {
	id := fmt.Sprintf("%06d", h.nextID)
	h.nextID++
	return id
}
