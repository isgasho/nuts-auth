package api

import (
	"context"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/nuts-foundation/nuts-proxy/api/auth"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

type API struct {
	config *Config
	server *http.Server
	router *chi.Mux
}

func (api *API) Start() {
	logrus.Infof("starting with httpPort: %d", api.config.Port)

	addr := fmt.Sprintf(":%d", api.config.Port)
	api.server = &http.Server{Addr: addr, Handler: api.router}

	err := api.server.ListenAndServe() // blocks

	if err != http.ErrServerClosed {
		logrus.WithError(err).Error("Http server stopped unexpected")
	} else {
		logrus.WithError(err).Info("Http server stopped")
	}
}

func (api *API) Shutdown() {
	if api.server != nil {
		logrus.Info("Shutting down the server")
		ctx, _ := context.WithTimeout(context.Background(), 10*time.Minute)
		if err := api.server.Shutdown(ctx); err != nil {
			logrus.WithError(err).Error("Failed to shutdown the server")

		}
		api.server = nil
	}
}

func New(config *Config) *API {

	api := &API{
		config: config,
	}

	api.router = api.Router()

	return api
}

func (api *API) Router() *chi.Mux {
	// configure the router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(NewStructuredLogger(api.config.Logger))
	r.Use(ContentTypeMiddlewareFn("application/json"))
	r.Get("/", ApiRootHandler)
	r.Mount("/auth", auth.New().Handler())
	return r
}

func ApiRootHandler(writer http.ResponseWriter, _ *http.Request) {
	_, _ = writer.Write([]byte("Welcome Nuts proxy!!"))
}

func ContentTypeMiddlewareFn(contentType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}
