package gateway

import (
	"context"
	"errors"
	"fmt"
	"gin-demo/internal/gateway/middleware"
	"gin-demo/internal/gateway/routes"
	"gin-demo/internal/handler"
	"gin-demo/internal/user/repository"
	"gin-demo/internal/user/service"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
)

type Config struct {
	Gateway GatewayConfig `yaml:"Gateway"`
}

type GatewayConfig struct {
	AdminUserIDs []string `yaml:"AdminUserIDs"`
	Secret       string   `yaml:"Secret"`
}

type dependencies struct {
	authService   *service.AuthService //用于验证bearer jwt的
	clientService *service.ClientService
	userService   *service.UserService //AdminMiddleware 用它查 is_admin
	authHandler   *handler.AuthHandler
	adminHandler  *handler.AdminHandler
	clientHandler *handler.ClientHandler
	userHandler   *handler.UserHandler
}

func loadConfigFromYaml(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(data, &config)
	if config.Gateway.Secret == "" {
		return nil, errors.New("secret is required")
	}
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func buildDependecies(context context.Context) (*dependencies, *Config, error) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./configs/config.yaml"
	}
	config, err := loadConfigFromYaml(configPath)
	if err != nil {
		return nil, nil, err
	}

	userRepo, err := repository.NewDynamoUserRepository(context)
	if err != nil {
		return nil, nil, err
	}
	sessionRepo, err := repository.NewDynamoSessionRepository(context)
	if err != nil {
		return nil, nil, err
	}

	authTokenRepo, err := repository.NewDynamoAuthTokenRepository(context)
	if err != nil {
		return nil, nil, err
	}
	accessTokenRepo, err := repository.NewDynamoAccessTokenRepository(context)
	if err != nil {
		return nil, nil, err
	}
	clientRepo, err := repository.NewDynamoClientRepository(context)
	if err != nil {
		return nil, nil, err
	}

	refreshTokenRepo, err := repository.NewDynamoRefreshTokenRepository(context)
	if err != nil {
		return nil, nil, err
	}
	sessionService := service.NewSessionService(sessionRepo)

	authService := service.NewAuthService(userRepo, sessionService, authTokenRepo, accessTokenRepo, refreshTokenRepo, clientRepo, config.Gateway.Secret)
	clientService := service.NewClientService(clientRepo)
	userService := service.NewUserService(userRepo)
	accountService := service.NewAccountService(userRepo, sessionService, authService)
	authHandler := handler.NewAuthHandler(authService, accountService, userService, clientService)
	adminHandler := handler.NewAdminHandler(authService)
	clientHandler := handler.NewClientHandler(clientService)
	userHandler := handler.NewUserHandler(userService)

	return &dependencies{
		authService:   authService,
		authHandler:   authHandler,
		adminHandler:  adminHandler,
		clientHandler: clientHandler,
		userHandler:   userHandler,
		clientService: clientService,
		userService:   userService,
	}, config, nil
}

func Run(ctx context.Context) error {
	dependencies, config, err := buildDependecies(ctx)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	router := buildRouter(dependencies, config)
	if router == nil {
		return fmt.Errorf("Build router failed")
	}
	return router.Run(":8080")
}

func buildRouter(deps *dependencies, config *Config) *gin.Engine {
	router := gin.New()

	//在访问端口前会先调用一遍方法
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORSMiddleware())
	router.Use(middleware.RateLimitMiddleware(20, 100))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	routes.RegisterClientRoutes(router, deps.clientHandler)
	routes.RegisterAdminRoutes(router, deps.adminHandler, deps.clientHandler, deps.authService, deps.userService, config.Gateway.AdminUserIDs)
	routes.RegisterAuthRoutes(router, deps.authHandler, deps.authService, deps.clientService)
	return router
}
