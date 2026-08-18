package main


import (
	"context"
	"log"

	"gin-demo/internal/gateway"
)

//在这启动gateway的服务，在8080端口
func main(){
	if err := gateway.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}