package httpserver

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"certus/internal/federation"
)

func (s *server) listIdentitySources(w http.ResponseWriter, r *http.Request) {
	sources, err := s.identitySources.List(r.Context())
	if err != nil {
		s.logger.Error("list identity sources", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取身份源失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": sources})
}

func (s *server) getIdentitySource(w http.ResponseWriter, r *http.Request) {
	source, err := s.identitySources.Find(r.Context(), r.PathValue("sourceID"))
	if errors.Is(err, federation.ErrSourceNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "身份源不存在")
		return
	}
	if err != nil {
		s.logger.Error("find identity source", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取身份源失败")
		return
	}
	writeJSON(w, http.StatusOK, source)
}

func (s *server) createIdentitySource(w http.ResponseWriter, r *http.Request) {
	var input federation.CreateSource
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	source, err := s.identitySources.Create(r.Context(), input)
	if identitySourceError(w, err) {
		return
	}
	w.Header().Set("Location", "/api/v1/admin/identity-sources/"+source.ID)
	writeJSON(w, http.StatusCreated, source)
}

func (s *server) replaceIdentitySource(w http.ResponseWriter, r *http.Request) {
	var input federation.ReplaceSource
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	source, err := s.identitySources.Replace(r.Context(), r.PathValue("sourceID"), input)
	if identitySourceError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, source)
}

func (s *server) archiveIdentitySource(w http.ResponseWriter, r *http.Request) {
	sourceID := r.PathValue("sourceID")
	clients, err := s.clients.List(r.Context())
	if err != nil {
		s.logger.Error("list clients before identity source archive", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "检查身份源使用情况失败")
		return
	}
	for _, item := range clients {
		if item.ArchivedAt == nil && slices.Contains(item.IdentitySourceIDs, sourceID) {
			writeProblem(w, http.StatusConflict, "source_in_use", "身份源仍被接入系统使用，请先解除绑定")
			return
		}
	}
	err = s.identitySources.Archive(r.Context(), sourceID)
	if identitySourceError(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) probeIdentitySource(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	err := s.identitySources.Probe(
		ctx,
		r.PathValue("sourceID"),
		s.cfg.Issuer+"/login/oidc/callback",
		s.outbound,
	)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "available",
			"checked_at": s.now().UTC(),
		})
	case errors.Is(err, federation.ErrSourceNotFound):
		writeProblem(w, http.StatusNotFound, "not_found", "身份源不存在")
	case errors.Is(err, federation.ErrSourceArchived):
		writeProblem(w, http.StatusConflict, "source_archived", "已归档的身份源不能检测")
	case errors.Is(err, federation.ErrSourceDisabled):
		writeProblem(w, http.StatusConflict, "source_disabled", "请先启用身份源再检测")
	case errors.Is(err, federation.ErrSourceEncryptionUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "source_encryption_unavailable", "身份源密钥无法解密")
	default:
		s.logger.Warn("probe identity source", "source_id", r.PathValue("sourceID"), "error", err)
		writeProblem(w, http.StatusBadGateway, "identity_source_unavailable", "身份源连接检测失败")
	}
}

func identitySourceError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, federation.ErrSourceNotFound):
		writeProblem(w, http.StatusNotFound, "not_found", "身份源不存在")
	case errors.Is(err, federation.ErrSourceConflict):
		writeProblem(w, http.StatusConflict, "source_exists", "身份源标识已存在")
	case errors.Is(err, federation.ErrSourceArchived):
		writeProblem(w, http.StatusConflict, "source_archived", "已归档的身份源不能修改")
	case errors.Is(err, federation.ErrSourceEncryptionUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "source_encryption_unavailable", "请先配置身份源密钥加密密钥")
	case errors.Is(err, federation.ErrInvalidSource):
		writeProblem(w, http.StatusBadRequest, "invalid_identity_source", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, "server_error", "保存身份源失败")
	}
	return true
}
