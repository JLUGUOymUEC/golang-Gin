package handler

import (
	"net/http"

	"gin-demo/internal/user/repository"
	"gin-demo/internal/user/service"

	"github.com/gin-gonic/gin"
)

type ClientHandler struct {
	clientService *service.ClientService
}

type createClientRequest struct {
	AppName           string   `json:"app_name" binding:"required"`
	RedirectURI       string   `json:"redirect_uri" binding:"required"`
	AllowedGrantTypes []string `json:"allowed_grant_types"`
	AllowedScopes     []string `json:"allowed_scopes"`
}

type clientResponse struct {
	ClientID          string   `json:"client_id"`
	AppName           string   `json:"app_name"`
	RedirectURI       string   `json:"redirect_uri"`
	AllowedGrantTypes []string `json:"allowed_grant_types"`
	AllowedScopes     []string `json:"allowed_scopes"`
	IsActive          bool     `json:"is_active"`
	CreatedAt         int64    `json:"created_at"`
	UpdatedAt         int64    `json:"updated_at"`
}

func NewClientHandler(clientService *service.ClientService) *ClientHandler {
	return &ClientHandler{clientService: clientService}
}

func (h *ClientHandler) CreateClient(c *gin.Context) {
	var req createClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client, clientSecret, err := h.clientService.CreateClient(c.Request.Context(), service.CreateClientInput{
		AppName:           req.AppName,
		RedirectURI:       req.RedirectURI,
		AllowedGrantTypes: req.AllowedGrantTypes,
		AllowedScopes:     req.AllowedScopes,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"client":        newClientResponse(client),
		"client_secret": clientSecret,
	})
}

func (h *ClientHandler) GetClient(c *gin.Context) {
	client, err := h.clientService.GetClientByID(c.Request.Context(), c.Param("clientID"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"client": newClientResponse(client)})
}

func (h *ClientHandler) ListClients(c *gin.Context) {
	var req struct {
		Limit  int32  `form:"limit"`
		Cursor string `form:"cursor"`
	}
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	clients, nextCursor, err := h.clientService.ListClients(c.Request.Context(), req.Limit, req.Cursor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	response := make([]clientResponse, 0, len(clients))
	for _, client := range clients {
		response = append(response, newClientResponse(client))
	}
	c.JSON(http.StatusOK, gin.H{"clients": response, "next_cursor": nextCursor})
}

func (h *ClientHandler) DeactivateClient(c *gin.Context) {
	if err := h.clientService.DeactivateClient(c.Request.Context(), c.Param("clientID")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func newClientResponse(client *repository.OAuthClient) clientResponse {
	return clientResponse{
		ClientID:          client.ClientID,
		AppName:           client.AppName,
		RedirectURI:       client.RedirectURI,
		AllowedGrantTypes: client.AllowedGrantTypes,
		AllowedScopes:     client.AllowedScopes,
		IsActive:          client.IsActive,
		CreatedAt:         client.CreatedAt,
		UpdatedAt:         client.UpdatedAt,
	}
}
