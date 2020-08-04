package engine

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nuts-foundation/nuts-auth/api"
	"github.com/nuts-foundation/nuts-auth/pkg"
	nutsGo "github.com/nuts-foundation/nuts-go-core"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	Any(path string, h echo.HandlerFunc, mi ...echo.MiddlewareFunc) []*echo.Route
	Use(middleware ...echo.MiddlewareFunc)
}

// NewAuthEngine creates and returns a new AuthEngine instance.
func NewAuthEngine() *nutsGo.Engine {

	authBackend := pkg.AuthInstance()

	return &nutsGo.Engine{
		Cmd:       cmd(),
		Config:    &authBackend.Config,
		ConfigKey: "auth",
		Configure: authBackend.Configure,
		FlagSet:   flagSet(),
		Name:      "Auth",
		Routes: func(router nutsGo.EchoRouter) {
			// Mount the irma-app routes
			routerWithAny := router.(EchoRouter)
			irmaEchoHandler := echo.WrapHandler(authBackend.IrmaServer.HandlerFunc())
			routerWithAny.Any("/auth/irmaclient/*", irmaEchoHandler)

			// Mount the Auth-api routes
			api.RegisterHandlers(router, &api.Wrapper{Auth: authBackend})

			checkConfig(authBackend.Config)

			config := pkg.AuthInstance().Config

			if config.EnableCORS {
				logrus.Debug("enabling CORS")
				routerWithAny.Use(middleware.CORS())
			}
		},
	}
}

func cmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "auth",
		Short: "commands related to authentication",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "server",
		Short: "Run standalone auth server",
		RunE: func(cmd *cobra.Command, args []string) error {
			authEngine := pkg.AuthInstance()
			echoServer := echo.New()
			echoServer.HideBanner = true
			echoServer.Use(middleware.Logger())

			if authEngine.Config.EnableCORS {
				echoServer.Use(middleware.CORS())
			}

			checkConfig(authEngine.Config)

			// Mount the irma-app routes
			irmaServer, err := pkg.GetIrmaServer(authEngine.Config)
			if err != nil {
				return err
			}
			irmaClientHandler := irmaServer.HandlerFunc()
			irmaEchoHandler := echo.WrapHandler(irmaClientHandler)
			echoServer.Any("/auth/irmaclient/*", irmaEchoHandler)

			// Mount the Nuts-Auth routes
			api.RegisterHandlers(echoServer, &api.Wrapper{Auth: authEngine})

			// Start the server
			return echoServer.Start(authEngine.Config.Address)
		},
	})

	return cmd
}

func checkConfig(config pkg.AuthConfig) {
	if config.IrmaSchemeManager == "" {
		logrus.Fatal("IrmaSchemeManager must be set. Valid options are: [pbdf|irma-demo]")
	}
	if nutsGo.NutsConfig().InStrictMode() && config.IrmaSchemeManager != "pbdf" {
		logrus.Fatal("In strictmode the only valid irma-scheme-manager is 'pbdf'")

	}
}

func flagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("auth", pflag.ContinueOnError)

	defs := pkg.DefaultAuthConfig()
	flags.String(pkg.ConfIrmaSchemeManager, defs.IrmaSchemeManager, fmt.Sprintf("The IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo', default: %s", defs.IrmaSchemeManager))
	flags.String(pkg.ConfAddress, defs.Address, fmt.Sprintf("Interface and port for http server to bind to, default: %s", defs.Address))
	flags.String(pkg.PublicURL, defs.PublicUrl, "Public URL which can be reached by a users IRMA client")
	flags.String(pkg.ConfMode, defs.Mode, "server or client, when client it does not start any services so that CLI commands can be used.")
	flags.String(pkg.ConfIrmaConfigPath, defs.IrmaConfigPath, "path to IRMA config folder. If not set, a tmp folder is created.")
	flags.String(pkg.ConfActingPartyCN, defs.ActingPartyCn, "The acting party Common name used in contracts")
	flags.Bool(pkg.ConfSkipAutoUpdateIrmaSchemas, defs.SkipAutoUpdateIrmaSchemas, "set if you want to skip the auto download of the irma schemas every 60 minutes.")
	flags.Bool(pkg.ConfEnableCORS, defs.EnableCORS, "Set if you want to allow CORS requests. This is useful when you want browsers to directly communicate with the nuts node.")

	return flags
}
