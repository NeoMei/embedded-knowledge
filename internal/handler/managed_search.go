package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/Tencent/WeKnora/internal/errors"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/gin-gonic/gin"
)

type managedSearchService interface {
	ManagedHybridSearch(context.Context, string, string) (*types.RetrievalResult, error)
	AuthorizeManagedSearch(context.Context, uint64, string, string, string, []byte, string, string) error
}

func (h *KnowledgeBaseHandler) ManagedHybridSearch(c *gin.Context) {
	_, kbID, tenant, _, err := h.validateAndGetKnowledgeBase(c)
	if err != nil {
		c.Error(err)
		return
	}
	svc, ok := h.service.(managedSearchService)
	if !ok {
		c.Error(errors.NewForbiddenError("Managed search unavailable"))
		return
	}
	raw, readErr := io.ReadAll(io.LimitReader(c.Request.Body, 32769))
	if readErr != nil || len(raw) > 32768 {
		c.Error(errors.NewBadRequestError("Invalid request parameters"))
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var body struct {
		Capability string `json:"capability"`
	}
	if dec.Decode(&body) != nil || body.Capability == "" || len(body.Capability) > 16384 {
		c.Error(errors.NewBadRequestError("Invalid request parameters"))
		return
	}
	if _, err = dec.Token(); err != io.EOF {
		c.Error(errors.NewBadRequestError("Invalid request parameters"))
		return
	}
	ctx := types.WithExecutionTenant(c.Request.Context(), tenant)
	proof := c.Request.Header.Values("X-WeKnora-Managed-Proof")
	if len(proof) != 1 || svc.AuthorizeManagedSearch(ctx, tenant, kbID, c.Request.Method, c.Request.URL.Path, raw, body.Capability, proof[0]) != nil {
		c.Error(errors.NewForbiddenError("Managed search unavailable"))
		return
	}
	result, err := svc.ManagedHybridSearch(ctx, kbID, body.Capability)
	if err != nil || result == nil {
		c.Error(errors.NewForbiddenError("Managed search unavailable"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": result.Results, "meta": result.Meta})
}
