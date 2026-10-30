package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	werrors "github.com/Tencent/WeKnora/internal/errors"
	"github.com/Tencent/WeKnora/internal/logger"
	"github.com/Tencent/WeKnora/internal/managedcapability"
	"github.com/Tencent/WeKnora/internal/tracing/langfuse"
	"github.com/Tencent/WeKnora/internal/types"
	secutils "github.com/Tencent/WeKnora/internal/utils"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

// CreateKnowledgeFromPath indexes a file where it already lives. Nothing is
// copied into storage: the record stores a ref:// path, and every later read
// (parse, reparse, preview, clone) opens that path.
//
// It is idempotent per path, so a caller that rescans a directory can register
// every file on each pass and only changed content needs a reparse.
func (s *knowledgeService) CreateKnowledgeFromPath(
	ctx context.Context,
	kbID string,
	path string,
	title string,
	folderPath string,
	metadata map[string]string,
	tagIDs []string,
	channel string,
	processOverrides *types.KnowledgeProcessOverrides,
) (*types.Knowledge, error) {
	logReferencePath(ctx, path, "")

	absPath, err := secutils.ValidateReferencePath(path)
	if err != nil {
		if _, managed := ctx.Value(managedReferenceKey{}).(managedcapability.Binding); managed {
			logger.Error(ctx, "Invalid managed reference path")
		} else {
			logger.Errorf(ctx, "Invalid reference path: %v", err)
		}
		return nil, werrors.NewBadRequestError("无效的文件路径").WithDetails(err.Error())
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, werrors.NewBadRequestError("无法读取文件").WithDetails(err.Error())
	}
	maxSizeMB := secutils.GetMaxFileSizeMB()
	if info.Size() > maxSizeMB*1024*1024 {
		return nil, werrors.NewBadRequestError(fmt.Sprintf("文件大小不能超过%dMB", maxSizeMB))
	}

	fileName := strings.TrimSpace(title)
	if fileName == "" {
		fileName = filepath.Base(absPath)
	}
	safeName, ok := secutils.ValidateInput(fileName)
	if !ok {
		return nil, werrors.NewValidationError("文件名包含非法字符")
	}
	fileName = safeName

	if IsVideoType(getFileType(fileName)) {
		return nil, werrors.NewBadRequestError("暂不支持视频文件")
	}
	if !isValidFileType(fileName) {
		return nil, ErrInvalidFileType
	}

	kb, err := s.kbService.GetKnowledgeBaseByID(ctx, kbID)
	if err != nil {
		return nil, err
	}
	if kb.Type == types.KnowledgeBaseTypeFAQ {
		return nil, werrors.NewBadRequestError("FAQ 知识库不支持文件导入")
	}
	if err := s.checkStorageEngineConfigured(ctx, kb); err != nil {
		return nil, err
	}

	if folderPath != "" {
		safeFolder, ok := secutils.ValidateInput(folderPath)
		if !ok {
			return nil, werrors.NewValidationError("文件夹路径包含非法字符")
		}
		folderPath = types.NormalizeKnowledgeFolderPath(safeFolder)
	}

	tenantID := ctx.Value(types.TenantIDContextKey).(uint64)
	filePath := secutils.ReferenceFilePath(absPath)

	// Same path, same document: return the existing record untouched. The
	// caller decides whether the content changed and needs a reparse.
	existing, err := s.repo.GetKnowledgeByFilePath(ctx, tenantID, kbID, filePath)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		binding, managed := ctx.Value(managedReferenceKey{}).(managedcapability.Binding)
		if (managed && (existing.ID != binding.KnowledgeID || existing.ManagedWorkID != binding.WorkID)) || (!managed && existing.ManagedWorkID != "") {
			return nil, ErrManagedWorkerUnavailable
		}
		logger.Infof(ctx, "Reference already registered, knowledge ID: %s", existing.ID)
		return existing, nil
	}

	fileHash, err := hashFileAtPath(absPath)
	if err != nil {
		return nil, err
	}

	var metadataJSON types.JSON
	if metadata != nil {
		metadataBytes, err := json.Marshal(metadata)
		if err != nil {
			return nil, err
		}
		metadataJSON = types.JSON(metadataBytes)
	}

	eff, err := resolveFileImportProcessConfig(ctx, kb, getFileType(fileName), processOverrides, nil)
	if err != nil {
		return nil, err
	}

	knowledge := &types.Knowledge{
		ID:               uuid.New().String(),
		TenantID:         tenantID,
		KnowledgeBaseID:  kbID,
		Type:             "file",
		Channel:          defaultChannel(channel),
		Title:            fileName,
		FileName:         fileName,
		FolderPath:       folderPath,
		FileType:         getFileType(fileName),
		FileSize:         info.Size(),
		FileHash:         fileHash,
		FilePath:         filePath,
		ParseStatus:      "pending",
		EnableStatus:     "disabled",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		EmbeddingModelID: kb.EmbeddingModelID,
		Metadata:         metadataJSON,
	}
	if binding, managed := ctx.Value(managedReferenceKey{}).(managedcapability.Binding); managed {
		knowledge.ID = binding.KnowledgeID
		knowledge.ManagedWorkID = binding.WorkID
	}
	if processOverrides != nil {
		if err := knowledge.SetProcessOverrides(processOverrides); err != nil {
			return nil, err
		}
	}

	atomic, ok := s.repo.(interface {
		CreateReferenceLocked(context.Context, *types.Knowledge) (*types.Knowledge, bool, error)
	})
	if !ok {
		return nil, ErrManagedWorkerUnavailable
	}
	knowledge, created, err := atomic.CreateReferenceLocked(ctx, knowledge)
	if err != nil {
		return nil, err
	}
	if !created {
		return knowledge, nil
	}
	if err := s.setAndAttachKnowledgeTags(ctx, tenantID, kbID, knowledge, tagIDs); err != nil {
		return nil, err
	}

	enableQuestionGeneration := eff.QuestionGenerationConfig.Enabled
	questionCount := eff.QuestionGenerationConfig.QuestionCount
	if questionCount <= 0 {
		questionCount = 3
	}

	payload := types.DocumentProcessPayload{
		ManagedWorkID:            knowledge.ManagedWorkID,
		TenantID:                 tenantID,
		KnowledgeID:              knowledge.ID,
		KnowledgeBaseID:          kbID,
		FilePath:                 filePath,
		FileName:                 fileName,
		FileType:                 getFileType(fileName),
		EnableMultimodel:         eff.EnableMultimodel,
		EnableQuestionGeneration: enableQuestionGeneration,
		QuestionCount:            questionCount,
		Language:                 types.LanguageFromContextOrDefault(ctx),
	}
	langfuse.InjectTracing(ctx, &payload)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		s.markKnowledgeEnqueueFailed(ctx, knowledge)
		return knowledge, nil
	}
	task := asynq.NewTask(
		types.TypeDocumentProcess,
		payloadBytes,
		documentProcessTaskOptions(s.config, asynq.MaxRetry(3))...,
	)
	if _, err := s.task.Enqueue(task); err != nil {
		logger.Errorf(ctx, "Failed to enqueue reference process task: %v", err)
		s.markKnowledgeEnqueueFailed(ctx, knowledge)
		return knowledge, nil
	}

	recordKBActivity(ctx, s.audit, tenantID, kbID, types.AuditActionKnowledgeCreated,
		"knowledge", knowledge.ID, types.AuditOutcomeAccepted, map[string]any{
			"title": knowledge.Title, "source_type": "file", "file_type": knowledge.FileType,
			"processing_status": "pending", "trigger": kbActivityTrigger(ctx), "ingest": "reference",
		})
	logReferencePath(ctx, absPath, knowledge.ID)
	return knowledge, nil
}

// hashFileAtPath is the reference counterpart of calculateFileHash: it hashes
// the file where it lives, at registration time, so the caller can later tell
// "same path, new content" without the backend re-reading it on a scan.
func hashFileAtPath(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func logReferencePath(ctx context.Context, path, knowledgeID string) {
	if _, managed := ctx.Value(managedReferenceKey{}).(managedcapability.Binding); managed {
		if knowledgeID == "" {
			logger.Info(ctx, "Start creating managed knowledge from reference")
		} else {
			logger.Infof(ctx, "Managed knowledge from reference created, ID: %s", knowledgeID)
		}
		return
	}
	if knowledgeID == "" {
		logger.Infof(ctx, "Start creating knowledge from path: %s", path)
	} else {
		logger.Infof(ctx, "Knowledge from path created, ID: %s, path: %s", knowledgeID, path)
	}
}
