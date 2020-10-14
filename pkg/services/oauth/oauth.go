/*
 * Nuts auth
 * Copyright (C) 2020. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package oauth

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	nutsCrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	nutsCryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	nutsRegistry "github.com/nuts-foundation/nuts-registry/pkg"
	errors2 "github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

const oauthKeyQualifier = "oauth"

// OauthBearerTokenMaxValidity is the number of seconds that a bearer token is valid
const OauthBearerTokenMaxValidity = 5

var ErrMissingVendorID = errors.New("missing VendorID")

// ErrMissingEndpoint is returned when no endpoints are found of type oauth
var ErrMissingEndpoint = errors.New("missing oauth endpoint in registry")

// ErrMissingCertificate is returned when the x5c header is missing in the JWT
var ErrMissingCertificate = errors.New("missing x5c header")

// ErrInvalidX5cHeader is returned when the x5c header is not a slice of strings
var ErrInvalidX5cHeader = errors.New("invalid x5c header")

var ValidOAuthJWTAlg = []string{
	jwt.SigningMethodPS256.Name,
	jwt.SigningMethodPS384.Name,
	jwt.SigningMethodPS512.Name,
	jwt.SigningMethodES256.Name,
	jwt.SigningMethodES384.Name,
	jwt.SigningMethodES512.Name,
}

type OAuthService struct {
	VendorID       core.PartyID
	Crypto         nutsCrypto.Client
	Registry       nutsRegistry.RegistryClient
	oauthKeyEntity nutsCryptoTypes.KeyIdentifier
}

func (s *OAuthService) Configure() (err error) {
	if s.VendorID.IsZero() {
		err = ErrMissingVendorID
		return
	}

	s.oauthKeyEntity = nutsCryptoTypes.KeyForEntity(nutsCryptoTypes.LegalEntity{URI: s.VendorID.String()}).WithQualifier(oauthKeyQualifier)

	if !s.Crypto.PrivateKeyExists(s.oauthKeyEntity) {
		logrus.Info("Missing OAuth JWT signing key, generating new one")
		s.Crypto.GenerateKeyPair(s.oauthKeyEntity, false)
	}
	return
}

// CreateJwtBearerToken creates a JwtBearerTokenResult containing a jwtBearerToken from a CreateJwtBearerTokenRequest.
func (s *OAuthService) CreateJwtBearerToken(request *services.CreateJwtBearerTokenRequest, endpointIdentifier string) (*services.JwtBearerTokenResult, error) {
	jti, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	jwtBearerToken := services.NutsJwtBearerToken{
		StandardClaims: jwt.StandardClaims{
			Audience:  endpointIdentifier,
			ExpiresAt: time.Now().Add(5 * time.Second).Unix(),
			Id:        jti.String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    request.Actor,
			NotBefore: 0,
			Subject:   request.Custodian,
		},
		AuthTokenContainer: request.IdentityToken,
		SubjectID:          request.Subject,
	}

	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(jwtBearerToken)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return nil, err
	}

	signingString, err := s.Crypto.SignJWTRFC003(keyVals)
	if err != nil {
		return nil, err
	}

	return &services.JwtBearerTokenResult{BearerToken: signingString}, nil
}

// ParseAndValidateJwtBearerToken validates the jwt signature and returns the containing claims
func (s *OAuthService) ParseAndValidateJwtBearerToken(acString string) (*services.NutsJwtBearerToken, error) {
	parser := &jwt.Parser{ValidMethods: ValidOAuthJWTAlg}
	token, err := parser.ParseWithClaims(acString, &services.NutsJwtBearerToken{}, func(token *jwt.Token) (i interface{}, e error) {
		// get public key from x5c header
		certificate, err := getCertificateFromHeaders(token)
		if err != nil {
			return nil, err
		}

		return certificate.PublicKey, nil
	})

	if token != nil && token.Valid {
		if claims, ok := token.Claims.(*services.NutsJwtBearerToken); ok {
			// this should be ok since it has already succeeded before
			claims.SigningCertificate, _ = getCertificateFromHeaders(token)
			return claims, nil
		}
	}

	return nil, err
}

func getCertificateFromHeaders(token *jwt.Token) (*x509.Certificate, error) {
	h, ok := token.Header["x5c"]
	if !ok {
		return nil, ErrMissingCertificate
	}
	i, ok := h.([]interface{})
	if !ok {
		return nil, ErrInvalidX5cHeader
	}
	if len(i) != 1 {
		return nil, ErrInvalidX5cHeader
	}
	c, ok := i[0].(string)
	if !ok {
		return nil, ErrInvalidX5cHeader
	}
	bytes, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		return nil, errors2.Wrap(err, ErrInvalidX5cHeader.Error())
	}
	return x509.ParseCertificate(bytes)
}

// ParseAndValidateAccessToken parses and validates an accesstoken string and returns a filled in NutsAccessToken.
func (s *OAuthService) ParseAndValidateAccessToken(accessToken string) (*services.NutsAccessToken, error) {
	parser := &jwt.Parser{ValidMethods: ValidOAuthJWTAlg}
	token, err := parser.ParseWithClaims(accessToken, &services.NutsAccessToken{}, func(token *jwt.Token) (i interface{}, e error) {
		// Check if the care provider which signed the token is managed by this node
		if !s.Crypto.PrivateKeyExists(s.oauthKeyEntity) {
			return nil, errors.New("invalid signature")
		}

		var sk crypto.Signer
		if sk, e = s.Crypto.GetPrivateKey(s.oauthKeyEntity); e != nil {
			return
		}

		// get public key
		i = sk.Public()
		return
	})

	if token != nil && token.Valid {
		if claims, ok := token.Claims.(*services.NutsAccessToken); ok {
			return claims, nil
		}
	}
	return nil, err
}

// BuildAccessToken builds an access token based on the oauth claims and the identity of the user provided by the identityValidationResult
// The token gets signed with the custodians private key and returned as a string.
func (s *OAuthService) BuildAccessToken(jwtBearerToken *services.NutsJwtBearerToken, identityValidationResult *services.ContractValidationResult) (string, error) {

	if identityValidationResult.ValidationResult != services.Valid {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("invalid contract"))
	}

	issuer := jwtBearerToken.Subject
	if issuer == "" {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("subject is missing"))
	}

	at := services.NutsAccessToken{
		StandardClaims: jwt.StandardClaims{
			// Expires in 15 minutes
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    issuer,
			Subject:   jwtBearerToken.Issuer,
		},
		SubjectID: jwtBearerToken.SubjectID,
		Scope:     jwtBearerToken.Scope,
		// based on
		// https://privacybydesign.foundation/attribute-index/en/pbdf.gemeente.personalData.html
		// https://privacybydesign.foundation/attribute-index/en/pbdf.pbdf.email.html
		// and
		// https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
		FamilyName: identityValidationResult.DisclosedAttributes["gemeente.personalData.familyname"],
		GivenName:  identityValidationResult.DisclosedAttributes["gemeente.personalData.firstnames"],
		Prefix:     identityValidationResult.DisclosedAttributes["gemeente.personalData.prefix"],
		Name:       identityValidationResult.DisclosedAttributes["gemeente.personalData.fullname"],
		Email:      identityValidationResult.DisclosedAttributes["pbdf.email.email"],
	}

	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(at)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return "", err
	}

	// Sign with the private key of the issuer
	token, err := s.Crypto.SignJWT(keyVals, s.oauthKeyEntity)
	if err != nil {
		return token, fmt.Errorf("could not build accessToken: %w", err)
	}

	return token, err
}

func parseTokenIssuer(issuer string) (core.PartyID, error) {
	if issuer == "" {
		return core.PartyID{}, ErrLegalEntityNotProvided
	}
	if result, err := core.ParsePartyID(issuer); err != nil {
		return core.PartyID{}, fmt.Errorf("invalid token issuer: %w", err)
	} else {
		return result, nil
	}
}

var ErrLegalEntityNotProvided = errors.New("legalEntity not provided")
