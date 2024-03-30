package endpoints

import (
	"github.com/bimal2614/ginBoilerplate/src/controllers"
	"github.com/gin-gonic/gin"
)

func SetupWebsocketRoutes(router *gin.Engine) {
	websocketController := controllers.NewWebsocketController()
	router.GET("/ws", websocketController.Websocket)
}
