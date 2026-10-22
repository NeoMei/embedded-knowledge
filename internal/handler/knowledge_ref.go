package handler

import (
	"net/http"

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
