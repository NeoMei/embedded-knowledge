package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/Tencent/WeKnora/internal/application/service"
	"github.com/Tencent/WeKnora/internal/errors"
	"github.com/Tencent/WeKnora/internal/logger"
	"github.com/Tencent/WeKnora/internal/types"
	secutils "github.com/Tencent/WeKnora/internal/utils"
	"github.com/gin-gonic/gin"
)

// CreateKnowledgeFromRefRequest registers a file that stays where it lives.
type CreateKnowledgeFromRefRequest struct {
	Path          string                           `json:"path" binding:"required"`
	Title         string                           `json:"title"`
	FolderPath    string                           `json:"folder_path"`
	Metadata      map[string]string                `json:"metadata"`
	TagIDs        []string                         `json:"tag_ids"`
	Channel       string                           `json:"channel"`
	ProcessConfig *types.KnowledgeProcessOverrides `json:"process_config"`
}

// CreateKnowledgeFromRef godoc
// @Summary      引用本地文件创建知识
// @Description  以绝对路径登记一个本地文件并解析入库，不复制文件。同一路径重复调用返回同一条记录。
// @Tags         知识管理
// @Accept       json
// @Produce      json
// @Param        id       path      string                          true  "知识库ID"
// @Param        request  body      CreateKnowledgeFromRefRequest   true  "文件路径"
// @Success      200      {object}  map[string]interface{}          "创建的知识"
// @Failure      400      {object}  errors.AppError                 "请求参数错误"
// @Security     Bearer
// @Security     ApiKeyAuth
// @Router       /knowledge-bases/{id}/knowledge/ref [post]
func (h *KnowledgeHandler) CreateKnowledgeFromRef(c *gin.Context) {
	ctx := c.Request.Context()

	_, kbID, effectiveTenantID, permission, err := h.validateKnowledgeBaseAccess(c)
	if err != nil {
		c.Error(err)
		return
	}
	ctx = types.WithExecutionTenant(c.Request.Context(), effectiveTenantID)

	if permission != types.OrgRoleAdmin && permission != types.OrgRoleEditor {
		c.Error(errors.NewForbiddenError("No permission to create knowledge"))
		return
	}

	var req CreateKnowledgeFromRefRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Error(errors.NewBadRequestError("Invalid request parameters").WithDetails(err.Error()))
		return
	}

	logger.Infof(ctx, "Creating knowledge from reference path, kb: %s", secutils.SanitizeForLog(kbID))
	knowledge, err := h.kgService.CreateKnowledgeFromPath(
		ctx, kbID, req.Path, req.Title, req.FolderPath, req.Metadata, req.TagIDs, req.Channel, req.ProcessConfig,
	)
	if err != nil {
		if appErr, ok := errors.IsAppError(err); ok {
			c.Error(appErr)
			return
		}
		logger.ErrorWithFields(ctx, err, nil)
		c.Error(errors.NewInternalServerError(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": knowledge})
}

type managedReferenceRequest struct {
	Path       string `json:"path"`
	Capability string `json:"capability"`
}
type managedReferenceService interface {
	CreateManagedKnowledgeFromPath(context.Context, string, string, string) (*types.Knowledge, error)
	AuthorizeManagedReference(context.Context, uint64, string, string, string, []byte, string, string) error
}

// CreateManagedKnowledgeFromRef accepts no actor or payer from the caller.
// The service independently verifies the signed work and live host authority.
func (h *KnowledgeHandler) CreateManagedKnowledgeFromRef(c *gin.Context) {
	_, kbID, tenantID, permission, err := h.validateKnowledgeBaseAccess(c)
	if err != nil {
		c.Error(err)
		return
	}
	if permission != types.OrgRoleAdmin && permission != types.OrgRoleEditor {
		c.Error(errors.NewForbiddenError("No permission to create knowledge"))
		return
	}
	managed, ok := h.kgService.(managedReferenceService)
	if !ok {
		c.Error(errors.NewBadRequestError("Managed knowledge unavailable"))
		return
	}
	raw, readErr := io.ReadAll(io.LimitReader(c.Request.Body, 32769))
	if readErr != nil || len(raw) > 32768 {
		c.Error(errors.NewBadRequestError("Invalid request parameters"))
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var req managedReferenceRequest
	if decoder.Decode(&req) != nil || req.Path == "" || req.Capability == "" || len(req.Capability) > 16384 {
		c.Error(errors.NewBadRequestError("Invalid request parameters"))
		return
	}
	if _, err = decoder.Token(); err != io.EOF {
		c.Error(errors.NewBadRequestError("Invalid request parameters"))
		return
	}
	ctx := types.WithExecutionTenant(c.Request.Context(), tenantID)
	proof := c.Request.Header.Values("X-WeKnora-Managed-Proof")
	if len(proof) != 1 || managed.AuthorizeManagedReference(ctx, tenantID, kbID, c.Request.Method, c.Request.URL.Path, raw, req.Capability, proof[0]) != nil {
		c.Error(errors.NewForbiddenError("Managed knowledge unavailable"))
		return
	}
	knowledge, err := managed.CreateManagedKnowledgeFromPath(ctx, kbID, req.Path, req.Capability)
	if err != nil {
		c.Error(errors.NewForbiddenError("Managed knowledge unavailable"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": knowledge})
}

// ManagedKnowledgeStatus exposes only a bound work's state after fresh proof.
func (h *KnowledgeHandler) ManagedKnowledgeStatus(c *gin.Context) {
	_, kbID, tenant, permission, err := h.validateKnowledgeBaseAccess(c)
	if err != nil {
		c.Error(err)
		return
	}
	if permission != types.OrgRoleAdmin && permission != types.OrgRoleEditor {
		c.Error(errors.NewForbiddenError("Managed knowledge unavailable"))
		return
	}
	svc, ok := h.kgService.(interface {
		ManagedKnowledgeStatus(context.Context, uint64, string, string, string, []byte, string, string) (*service.ManagedStatus, error)
	})
	if !ok {
		c.Error(errors.NewForbiddenError("Managed knowledge unavailable"))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 32769))
	if err != nil || len(raw) > 32768 {
		c.Error(errors.NewBadRequestError("Invalid request parameters"))
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request struct {
		Capability string `json:"capability"`
	}
	if decoder.Decode(&request) != nil || request.Capability == "" || len(request.Capability) > 16384 {
		c.Error(errors.NewBadRequestError("Invalid request parameters"))
		return
	}
	if _, err = decoder.Token(); err != io.EOF {
		c.Error(errors.NewBadRequestError("Invalid request parameters"))
		return
	}
	proof := c.Request.Header.Values("X-WeKnora-Managed-Proof")
	if len(proof) != 1 {
		c.Error(errors.NewForbiddenError("Managed knowledge unavailable"))
		return
	}
	ctx := types.WithExecutionTenant(c.Request.Context(), tenant)
	result, err := svc.ManagedKnowledgeStatus(ctx, tenant, kbID, c.Request.Method, c.Request.URL.Path, raw, request.Capability, proof[0])
	if err != nil || result == nil {
		c.Error(errors.NewForbiddenError("Managed knowledge unavailable"))
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": result})
}
