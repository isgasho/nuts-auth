package x509

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

var encodedJwt = `eyJ4NWMiOlsiTUlJSGN6Q0NCVnVnQXdJQkFnSVVIUFU4cVZYS3FEZXByWUhDQ1dLQmkrdkp0Vll3RFFZSktvWklodmNOQVFFTEJRQXdhakVMTUFrR0ExVUVCaE1DVGt3eERUQUxCZ05WQkFvTUJFTkpRa2N4RnpBVkJnTlZCR0VNRGs1VVVrNU1MVFV3TURBd05UTTFNVE13TVFZRFZRUUREQ3BVUlZOVUlGVmFTUzF5WldkcGMzUmxjaUJOWldSbGQyVnlhMlZ5SUc5d0lHNWhZVzBnUTBFZ1J6TXdIaGNOTWpBd056RTNNVEl6TkRFNVdoY05Nak13TnpFM01USXpOREU1V2pDQmhURUxNQWtHQTFVRUJoTUNUa3d4SURBZUJnTlZCQW9NRjFURHFYTjBJRnB2Y21kcGJuTjBaV3hzYVc1bklEQXpNUll3RkFZRFZRUUVEQTEwWlhOMExUa3dNREUzT1RRek1Rd3dDZ1lEVlFRcURBTktZVzR4RWpBUUJnTlZCQVVUQ1Rrd01EQXlNVEl4T1RFYU1CZ0dBMVVFQXd3UlNtRnVJSFJsYzNRdE9UQXdNVGM1TkRNd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNoVFloUEE3WDBTNWNWQnhHYzdHWi81RHZxSWVzaWowYUpadllMcVhrRmkzOU5EQjRLSDM4c3JIbHRGVWYyOVF3YlBSUm9KOEJJYXpFTnhkdTg4WUQvZXBKSGhmOUhpMkx1UGhoZmdSU3FjSnp4dDNPYStKME91YzdnZzBZaytnV01USkJ5R2ZSYlRQR3V5eVFFMnJOUFJteDRoOUNLSDZiNHVZam1ESDJWdXlhM3BtY0UrR2wxbmUvQnJjYnRsSmpCa2d6Vkw2cmVTYzdPUXhvbi9ZbmFRanhvakJpZ2xhT0hub2JESU9tczluQkZFQ29uUzVKNGZvb1VRVTg3anFMSGlHckJNL2xNdHlaOUVrblhGQ3U2U3VRb3ZDNlR1eUZ2c0JnT0MyNzNGZ0JaR2VybHkzbTFEVXczTlROUG15dlJEUXREWEJHTi9BVkVJLzR4VGdGL0FnTUJBQUdqZ2dMek1JSUM3ekJSQmdOVkhSRUVTakJJb0VZR0ExVUZCYUEvRmoweUxqRTJMalV5T0M0eExqRXdNRGN1T1RrdU1qRTRMVEV0T1RBd01ESXhNakU1TFU0dE9UQXdNREF6T0RJdE1EQXVNREF3TFRBd01EQXdNREF3TUF3R0ExVWRFd0VCL3dRQ01BQXdId1lEVlIwakJCZ3dGb0FVeWZBR0RwTGZOaThJZFRpODMrNUJlYkpkd0Y4d2dhc0dDQ3NHQVFVRkJ3RUJCSUdlTUlHYk1Hc0dDQ3NHQVFVRkJ6QUNobDlvZEhSd09pOHZkM2QzTG5WNmFTMXlaV2RwYzNSbGNpMTBaWE4wTG01c0wyTmhZMlZ5ZEhNdk1qQXhPVEExTURGZmRHVnpkRjkxZW1rdGNtVm5hWE4wWlhKZmJXVmtaWGRsY210bGNsOXZjRjl1WVdGdFgyTmhYMmN6TG1ObGNqQXNCZ2dyQmdFRkJRY3dBWVlnYUhSMGNEb3ZMMjlqYzNBdWRYcHBMWEpsWjJsemRHVnlMWFJsYzNRdWJtd3dnZ0VHQmdOVkhTQUVnZjR3Z2Zzd2dmZ0dDV0NFRUFHSGIyT0JWRENCNmpBL0JnZ3JCZ0VGQlFjQ0FSWXphSFIwY0hNNkx5OWhZMk5sY0hSaGRHbGxMbnB2Y21kamMzQXVibXd2WTNCekwzVjZhUzF5WldkcGMzUmxjaTVvZEcxc01JR21CZ2dyQmdFRkJRY0NBakNCbVF5QmxrTmxjblJwWm1sallXRjBJSFZwZEhOc2RXbDBaVzVrSUdkbFluSjFhV3RsYmlCMFpXNGdZbVZvYjJWMlpTQjJZVzRnWkdVZ1ZFVlRWQ0IyWVc0Z2FHVjBJRlZhU1MxeVpXZHBjM1JsY2k0Z1NHVjBJRlZhU1MxeVpXZHBjM1JsY2lCcGN5QnBiaUJuWldWdUlHZGxkbUZzSUdGaGJuTndjbUZyWld4cGFtc2dkbTl2Y2lCbGRtVnVkSFZsYkdVZ2MyTm9ZV1JsTGpBZkJnTlZIU1VFR0RBV0JnZ3JCZ0VGQlFjREJBWUtLd1lCQkFHQ053b0REREJqQmdOVkhSOEVYREJhTUZpZ1ZxQlVobEpvZEhSd09pOHZkM2QzTG5WNmFTMXlaV2RwYzNSbGNpMTBaWE4wTG01c0wyTmtjQzkwWlhOMFgzVjZhUzF5WldkcGMzUmxjbDl0WldSbGQyVnlhMlZ5WDI5d1gyNWhZVzFmWTJGZlp6TXVZM0pzTUIwR0ExVWREZ1FXQkJTWTBkclhRMEpINmhIdi9zejFTK3lyakVoU1F6QU9CZ05WSFE4QkFmOEVCQU1DQmtBd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQkFGMDdXWmhoNkx5ZWdjMjJscDIwb0x5K2tnUlB3Ti9TL0lTdkxGVEY0RFBBSTY2RmtVSnNGUmFmbXVhMFpsL0JPZ2U1SXZwMHM5dEVqaHBaMTZYNGVZQm1qOE1VMHhBTjM0OC9PakFtSUZTR0l1d2kxU2RyendIUnF2VUxmMHNWcXZUOEpEVTZkMHEvaVBPRThEYU9OWXppbUlkZ1dFOXBOODhBb1ptT3VkSDQzSjk3WkRnMXYrWnU3NnMwdFI4WXpXSElUVDEvbmJRbDUzeU9mR3dER1RSdk42T1hkelBMVXpUbGhmdEdYZUZPRmNrb0Q4c2NRTGFaV1loQTVaVDRxLzlncE02WXU1TTMzWVJ0empGek4yTWVWaFpsUmV5NUY1NmVWcDV6MkM0U3NnM2FCemkyandnRzExY3pvMVBGdldod21zckNTTFpJUHdhWFduQ3hnYW5FZkxzeXVKcmpuVXYyUXdaeldCT1VoRjhSN2FtUk9xUHN6VGJwNE9yZWUyWmFyc04wYzNSLzdYdmJvcVdhb3NRa3Q1MFlxOHpCQ0Z4clFMZkZKN1pUcEhHWENEQmtzcVg4WWVrZ2RxdDhIMmdSS2p2OVNLY2RjejA0a2VJUEIyRU85K2ZQTHcwckZqRGVLdFFjYmRXTDlFSHRNOHAwcXBmTHNLcUdqbXdSdHhYbVRYUHNVS0FKQ1RKdWI4cnVRZVpsQlhZVC91YjNEMER1RzB2YUlNcjE3aDZydEdYR1hDWFV2VUxYMzBnczFyS3VUVkZkR0xFRUdid3JHbFVUZUdHRXFQbU4xdWFmNWpEdkR1UDE5R2RTV0VZMW4xTjYvV1paODhVS2ZnZHpxSVlKemt1RzV6bGZLUWdEREJvZXNyd3BCZXlkTXo0M0diZEZieS8zUm9MNSJdLCJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSmFuIHRlc3QifQ.gs2Xe5uGLT8IzV6h9DDic_QilTj3CcPl4mefUSP_pwbPiyWsRL4pwKmfznmpltl_3_9Op6z4aOS4OdZQGPhHbDuuroZrZqq46uULU2LRBv7YkjhRQGQDoNPoC7otozxcKkOx6pl9nDTNaE5iOAgF-F_Ae6WYk5pNGgWmH3d4wZhVsqCdsokL-ATm_1ZSjIbxQ4LUVNY2Fnfc08ihT6gvN5cmbGWvMSeMCqd8reqffTnoYz02_Szy_hCYtvAjrUIpVzQYjdzYXNmxsTOYbXBAAFDJf8Zh_idn9PR7Gq8lWqcTR3DSgYU25CeC63afUasZvW3c78SUqr2nwN3n3T1bdw`

func TestNewJwtX509Validator(t *testing.T) {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	rootCert, rootCertKey, err := createTestRootCert()
	if !assert.NoError(t, err) {
		return
	}

	intermediateCert, intermediateCerKey, err := createIntermediateCert(rootCert, rootCertKey)
	if !assert.NoError(t, err) {
		return
	}

	leafCert, err := createLeafCert(intermediateCert, intermediateCerKey)
	if !assert.NoError(t, err) {
		return
	}

	roots.AddCert(rootCert)
	intermediates.AddCert(intermediateCert)
	vOptions := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}
	_, err = leafCert.Verify(vOptions)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok - validator with only a root", func(t *testing.T) {
		validator := NewJwtX509Validator(roots, nil, &contract.TemplateStore{})
		assert.NotNil(t, validator)
		token := &JwtX509Token{chain: []*x509.Certificate{leafCert, intermediateCert}}
		leaf, chain, err := validator.verifyCertChain(token)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, leafCert, leaf)
		assert.Len(t, chain[0], 3)

		t.Run("nok - root is not a root", func(t *testing.T) {
			validator := NewJwtX509Validator(intermediates, nil, &contract.TemplateStore{})
			token := &JwtX509Token{chain: []*x509.Certificate{leafCert}}
			leaf, chain, err := validator.verifyCertChain(token)
			assert.Nil(t, leaf)
			assert.Nil(t, chain)
			assert.Error(t, err)
		})
	})

	t.Run("nok - complete chain in token, but not part of roots", func(t *testing.T) {
		roots := x509.NewCertPool()
		validator := NewJwtX509Validator(roots, nil, &contract.TemplateStore{})
		token := &JwtX509Token{chain: []*x509.Certificate{leafCert, intermediateCert, rootCert}}
		_, _, err := validator.verifyCertChain(token)
		assert.Error(t, err)
		assert.EqualError(t, err, "unable to verify certificate chain: x509: certificate signed by unknown authority")
	})

	t.Run("ok - validator with root and intermediates", func(t *testing.T) {
		validator := NewJwtX509Validator(roots, intermediates, &contract.TemplateStore{})
		assert.NotNil(t, validator)
		token := &JwtX509Token{chain: []*x509.Certificate{leafCert}}
		leaf, chain, err := validator.verifyCertChain(token)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, leafCert, leaf)
		assert.Len(t, chain[0], 3)

	})
	t.Run("nok - validator without roots", func(t *testing.T) {
		validator := NewJwtX509Validator(nil, roots, &contract.TemplateStore{})
		assert.NotNil(t, validator)
		token := &JwtX509Token{chain: []*x509.Certificate{leafCert, intermediateCert}}
		_, _, err := validator.verifyCertChain(token)
		assert.Error(t, err)
	})
}

func TestJwtX509Validator_Parse(t *testing.T) {
	pathPrefix := "../../../testdata/certs/uzi-test/"
	rootCert, err := readCertFromFile(pathPrefix + "test_zorg_csp_root_ca_g3.cer")
	if !assert.NoError(t, err) {
		return
	}
	intermediate1, err := readCertFromFile(pathPrefix + "test_zorg_csp_level_2_persoon_ca_g3.cer")
	if !assert.NoError(t, err) {
		return
	}
	intermediate2, err := readCertFromFile(pathPrefix + "test_uzi-register_medewerker_op_naam_ca_g3.cer")
	if !assert.NoError(t, err) {
		return
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate1)
	intermediates.AddCert(intermediate2)

	validator := JwtX509Validator{
		roots:         roots,
		intermediates: intermediates,
	}

	signedContract, err := validator.Parse(encodedJwt)
	if !assert.NoError(t, err) {
		return
	}

	expected := map[string]string{
		"agbCode":  "00000000",
		"cardType": "N",
		"oidCa":    "2.16.528.1.1007.99.218",
		"orgID":    "90000382",
		"rollCode": "00.000",
		"uziNr":    "900021219",
		"version":  "1",
	}

	assert.Equal(t, expected, signedContract.SignerAttributes())

	err = validator.Verify(signedContract)
	assert.NoError(t, err)
}
