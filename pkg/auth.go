package pkg

import (
	"fmt"
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

// ConfAddress is the config key for the address the http server listens on
const ConfAddress = "address"
// PublicURL is the config key for the public URL the http/irma server can be discovered
const PublicURL = "publicUrl"

// AuthClient is the interface which should be implemented for clients or mocks
type AuthClient interface {
	CreateContractSession(sessionRequest CreateSessionRequest, actingParty string) (*CreateSessionResult, error)
	ContractSessionStatus(sessionID string) (*SessionStatusResult, error)
	ContractByType(contractType ContractType, language Language, version Version) (*Contract, error)
	ValidateContract(request ValidationRequest) (*ValidationResult, error)
}

// Auth is the main struct of the Auth service
type Auth struct {
	Config                 AuthConfig
	configOnce             sync.Once
	configDone             bool
	ContractSessionHandler ContractSessionHandler
	ContractValidator      ContractValidator
}

// AuthConfig holds all the configuration params
type AuthConfig struct {
	Address        string
	PublicUrl      string
	IrmaConfigPath string
}

var instance *Auth
var oneBackend sync.Once

// AuthInstance create an returns a singleton of the Auth struct
func AuthInstance() *Auth {
	oneBackend.Do(func() {
		instance = &Auth{
			Config: AuthConfig{},
		}
	})

	return instance
}

// Configure the Auth struct by creating a validator and create an Irma server
func (auth *Auth) Configure() (err error) {
	auth.configOnce.Do(func() {

		validator := DefaultValidator{
			IrmaServer: GetIrmaServer(auth.Config),
		}
		auth.ContractSessionHandler = validator
		auth.ContractValidator = validator
		auth.configDone = true
	})

	return err
}

// CreateContractSession creates a session based on an IRMA contract. This allows the user to permit the application to
// use the Nuts Network in its name. The user can limit the application in time and scope. By signing it with IRMA other
// nodes in the network can verify the validity of the contract.
func (auth *Auth) CreateContractSession(sessionRequest CreateSessionRequest, actingParty string) (*CreateSessionResult, error) {

	// Step 1: Find the correct contract
	contract, err := ContractByType(sessionRequest.Type, sessionRequest.Language, sessionRequest.Version)
	if err != nil {
		return nil, err
	}

	// Step 2: Render the contract template with all the correct values
	message, err := contract.renderTemplate(map[string]string{
		"acting_party": actingParty,
	}, 0, 60*time.Minute)
	logrus.Debugf("contractMessage: %v", message)
	if err != nil {
		logMsg := fmt.Sprintf("Could not render contract template of type %v: %v", contract.Type, err)
		logrus.Error(logMsg)
		return nil, errors.New(logMsg)
	}

	// Step 3: Put the contract in an IMRA envelope
	signatureRequest := &irma.SignatureRequest{
		Message: message,
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{
				Type: irma.ActionSigning,
			},
			Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
				Label:      "AGB-Code",
				Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier(contract.SignerAttributes[0])},
			}}),
		},
	}

	// Step 4: Start an IRMA session
	sessionPointer, token, err := auth.ContractSessionHandler.StartSession(signatureRequest, func(result *server.SessionResult) {
		logrus.Infof("session done, result: %s", server.ToJson(result))
	})
	if err != nil {
		logrus.Error("error while creating session: ", err)
		return nil, err
	}
	logrus.Debugf("session created with token: %s", token)

	// Return the sessionPointer and sessionId
	createSessionResult := &CreateSessionResult{
		QrCodeInfo: *sessionPointer,
		SessionId:  token,
	}
	return createSessionResult, nil
}

// ContractByType returns a Contract of a certain type, language and version.
// If for the combination of type, version and language no contract can be found, the error is of type ErrContractNotFound
func (auth *Auth) ContractByType(contractType ContractType, language Language, version Version) (*Contract, error) {
	return ContractByType(contractType, language, version)
}

// ContractSessionStatus returns the current session status for a given sessionID.
// If the session is not found, the error is an ErrSessionNotFound and SessionStatusResult is nil
func (auth *Auth) ContractSessionStatus(sessionID string) (*SessionStatusResult, error) {
	if sessionStatus := auth.ContractSessionHandler.SessionStatus(SessionID(sessionID)); sessionStatus != nil {
		return sessionStatus, nil
	}
	return nil, xerrors.Errorf("sessionID %s: %w",sessionID, ErrSessionNotFound)
}

// ValidateContract validates a given contract. Currently two ContractType's are accepted: Irma and Jwt.
// Both types should be passed as a base64 encoded string in the ContractString of the request paramContractString of the request param
func (auth *Auth) ValidateContract(request ValidationRequest) (*ValidationResult, error) {
	if request.ContractFormat == IrmaFormat {
		return auth.ContractValidator.ValidateContract(request.ContractString, IrmaFormat, request.ActingPartyCN)
	} else if request.ContractFormat == JwtFormat {
		return auth.ContractValidator.ValidateJwt(request.ContractString, request.ActingPartyCN)
	}
	return nil, xerrors.Errorf("format %v: %w", request.ContractFormat, ErrUnknownContractFormat)
}
