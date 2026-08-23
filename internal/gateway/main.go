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
	Secret string `yaml:"Secret"`
}

type dependencies struct {
	authService *service.AuthService //用于验证bearer jwt的

	authHandler   *handler.AuthHandler
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

func buildDependecies(context context.Context) (*dependencies, error) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./configs/config.yaml"
	}
	config, err := loadConfigFromYaml(configPath)
	if err != nil {
		return nil, err
	}

	userRepo, err := repository.NewDynamoUserRepository(context)
	if err != nil {
		return nil, err
	}
	sessionRepo, err := repository.NewDynamoSessionRepository(context)
	if err != nil {
		return nil, err
	}

	authTokenRepo, err := repository.NewDynamoAuthTokenRepository(context)
	if err != nil {
		return nil, err
	}
	accessTokenRepo, err := repository.NewDynamoAccessTokenRepository(context)
	if err != nil {
		return nil, err
	}
	clientRepo, err := repository.NewDynamoClientRepository(context)
	if err != nil {
		return nil, err
	}

	refreshTokenRepo, err := repository.NewDynamoRefreshTokenRepository(context)
	if err != nil {
		return nil, err
	}
	sessionService := service.NewSessionService(sessionRepo)

	authService := service.NewAuthService(userRepo, sessionService, authTokenRepo, accessTokenRepo, refreshTokenRepo, config.Gateway.Secret)
	clientService := service.NewClientService(clientRepo)
	userService := service.NewUserService(userRepo)
	accountService := service.NewAccountService(userRepo, sessionService)
	authHandler := handler.NewAuthHandler(authService, accountService ,userService)
	clientHandler := handler.NewClientHandler(clientService)
	userHandler := handler.NewUserHandler(userService)

	return &dependencies{
		authService:   authService,
		authHandler:   authHandler,
		clientHandler: clientHandler,
		userHandler:   userHandler,
	}, nil
}

func Run(ctx context.Context) error {
	dependencies, err := buildDependecies(ctx)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	router := buildRouter(dependencies)
	if router == nil {
		return fmt.Errorf("Build router failed")
	}
	return router.Run(":8080")
}

func buildRouter(deps *dependencies) *gin.Engine {
	router := gin.New()

	//在访问端口前会先调用一遍方法
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORSMiddleware())
	router.Use(middleware.RateLimitMiddleware(20, 100))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	routes.RegisterClientRoutes(router, deps.clientHandler, deps.authService)
	routes.RegisterAuthRoutes(router, deps.authHandler, deps.authService)
	return router
}
