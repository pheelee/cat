package scim2

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/elimity-com/scim"
	"github.com/elimity-com/scim/errors"
	"github.com/elimity-com/scim/filter"
	"github.com/elimity-com/scim/optional"
	"github.com/elimity-com/scim/schema"
)

type memoryResourceHandler struct {
	data   map[string]resourceData
	schema schema.Schema
}

func (h memoryResourceHandler) Create(r *http.Request, attributes scim.ResourceAttributes) (scim.Resource, error) {
	// create unique identifier
	rng := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec G404
	id := fmt.Sprintf("%06d", rng.Intn(999999))

	now := time.Now()
	h.data[id] = resourceData{
		attributes: attributes,
		meta: scim.Meta{
			Created:      &now,
			LastModified: &now,
			Version:      fmt.Sprintf("v%s", id),
		},
	}
	// return stored resource
	return scim.Resource{
		ID:         id,
		ExternalID: h.externalID(attributes),
		Attributes: attributes,
		Meta: scim.Meta{
			Created:      &now,
			LastModified: &now,
			Version:      fmt.Sprintf("v%s", id),
		},
	}, nil
}

func (h memoryResourceHandler) Delete(r *http.Request, id string) error {
	// check if resource exists
	_, ok := h.data[id]
	if !ok {
		return errors.ScimErrorResourceNotFound(id)
	}

	// delete(h.data, id)
	delete(h.data, id)
	return nil
}

func (h memoryResourceHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	res, ok := h.data[id]
	if !ok {
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}

	created, _ := time.ParseInLocation(time.RFC3339, fmt.Sprintf("%v", res.meta.Created), time.UTC)
	lastModified, _ := time.Parse(time.RFC3339, fmt.Sprintf("%v", res.meta.LastModified))

	// return resource with given identifier
	return scim.Resource{
		ID:         id,
		ExternalID: h.externalID(res.attributes),
		Attributes: res.attributes,
		Meta: scim.Meta{
			Created:      &created,
			LastModified: &lastModified,
			Version:      fmt.Sprintf("%v", res.meta.Version),
		},
	}, nil
}

func (h memoryResourceHandler) GetAll(r *http.Request, params scim.ListRequestParams) (scim.Page, error) {
	if params.Count == 0 {
		return scim.Page{
			TotalResults: len(h.data),
		}, nil
	}

	resources := make([]scim.Resource, 0)
	i := 1

	for k, v := range h.data {
		if i > (params.StartIndex + params.Count - 1) {
			break
		}

		validator := filter.NewFilterValidator(params.FilterValidator.GetFilter(), h.schema)
		if err := validator.PassesFilter(v.attributes); err != nil {
			continue
		}

		if i >= params.StartIndex {
			resources = append(resources, scim.Resource{
				ID:         k,
				ExternalID: h.externalID(v.attributes),
				Attributes: v.attributes,
				Meta: scim.Meta{
					Created:      v.meta.Created,
					LastModified: v.meta.LastModified,
					Version:      fmt.Sprintf("%v", v.meta.Version),
				},
			})
		}
		i++
	}

	return scim.Page{
		TotalResults: len(h.data),
		Resources:    resources,
	}, nil
}

func (h memoryResourceHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	if h.shouldReturnNoContent(id, operations) {
		return scim.Resource{}, nil
	}

	for _, op := range operations {
		switch op.Op {
		case scim.PatchOperationAdd:
			if op.Path != nil {
				h.data[id].attributes[op.Path.String()] = op.Value
			} else {
				valueMap := op.Value.(map[string]interface{})
				for k, v := range valueMap {
					if arr, ok := h.data[id].attributes[k].([]interface{}); ok {
						arr = append(arr, v)
						h.data[id].attributes[k] = arr
					} else {
						h.data[id].attributes[k] = v
					}
				}
			}
		case scim.PatchOperationReplace:
			if op.Path != nil {
				h.data[id].attributes[op.Path.String()] = op.Value
			} else {
				valueMap := op.Value.(map[string]interface{})
				for k, v := range valueMap {
					h.data[id].attributes[k] = v
				}
			}
		case scim.PatchOperationRemove:
			h.data[id].attributes[op.Path.String()] = nil
		}
	}

	created, _ := time.ParseInLocation(time.RFC3339, fmt.Sprintf("%v", h.data[id].meta.Created), time.UTC)
	now := time.Now()

	// return resource with replaced attributes
	return scim.Resource{
		ID:         id,
		ExternalID: h.externalID(h.data[id].attributes),
		Attributes: h.data[id].attributes,
		Meta: scim.Meta{
			Created:      &created,
			LastModified: &now,
			Version:      fmt.Sprintf("%s.patch", h.data[id].meta.Version),
		},
	}, nil
}

func (h memoryResourceHandler) Replace(r *http.Request, id string, attributes scim.ResourceAttributes) (scim.Resource, error) {
	// check if resource exists
	u, ok := h.data[id]
	if !ok {
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}

	// replace (all) attributes
	h.data[id] = resourceData{
		attributes: attributes,
		meta:       u.meta,
	}
	now := time.Now()
	// return resource with replaced attributes
	return scim.Resource{
		ID:         id,
		ExternalID: h.externalID(attributes),
		Attributes: attributes,
		Meta: scim.Meta{
			Created:      u.meta.Created,
			LastModified: &now,
			Version:      fmt.Sprintf("%s.replace", u.meta.Version),
		},
	}, nil
}

func (h memoryResourceHandler) externalID(attributes scim.ResourceAttributes) optional.String {
	if eID, ok := attributes["externalId"]; ok {
		externalID, ok := eID.(string)
		if !ok {
			return optional.String{}
		}
		return optional.NewString(externalID)
	}
	return optional.String{}
}

func (h memoryResourceHandler) noContentOperation(id string, op scim.PatchOperation) bool {
	isRemoveOp := strings.EqualFold(op.Op, scim.PatchOperationRemove)

	dataValue, ok := h.data[id]
	if !ok {
		return isRemoveOp
	}
	var path string
	if op.Path != nil {
		path = op.Path.String()
	}
	attrValue, ok := dataValue.attributes[path]
	if ok && attrValue == op.Value {
		return true
	}
	if !ok && isRemoveOp {
		return true
	}

	switch opValue := op.Value.(type) {
	case map[string]interface{}:
		for k, v := range opValue {
			if v == dataValue.attributes[k] {
				return true
			}
		}

	case []map[string]interface{}:
		for _, m := range opValue {
			for k, v := range m {
				if v == dataValue.attributes[k] {
					return true
				}
			}
		}
	}
	return false
}

func (h memoryResourceHandler) shouldReturnNoContent(id string, ops []scim.PatchOperation) bool {
	for _, op := range ops {
		if h.noContentOperation(id, op) {
			continue
		}
		return false
	}
	return true
}
