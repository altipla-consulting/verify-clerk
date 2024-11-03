package clerk

import (
	"context"
	"fmt"
	"sync"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/jwks"
	"github.com/clerk/clerk-sdk-go/v2/jwt"
	"github.com/clerk/clerk-sdk-go/v2/user"
)

type Verifier[CustomClaims any] struct {
	mx   sync.RWMutex
	keys map[string]*clerk.JSONWebKey

	jwksClient  *jwks.Client
	clerkClient *user.Client
}

func NewVerifier[CustomClaims any](apiKey string) *Verifier[CustomClaims] {
	config := &clerk.ClientConfig{
		BackendConfig: clerk.BackendConfig{
			Key: clerk.String(apiKey),
		},
	}
	return &Verifier[CustomClaims]{
		keys:        make(map[string]*clerk.JSONWebKey),
		jwksClient:  jwks.NewClient(config),
		clerkClient: user.NewClient(config),
	}
}

func (v *Verifier[CustomClaims]) getKey(keyID string) *clerk.JSONWebKey {
	v.mx.RLock()
	defer v.mx.RUnlock()
	return v.keys[keyID]
}

func (v *Verifier[CustomClaims]) Verify(ctx context.Context, token string) (*clerk.SessionClaims, *CustomClaims, error) {
	unsafeClaims, err := jwt.Decode(ctx, &jwt.DecodeParams{Token: token})
	if err != nil {
		return nil, nil, fmt.Errorf("verify-clerk: cannot decode token: %w", err)
	}
	jwk := v.getKey(unsafeClaims.KeyID)
	if jwk == nil {
		jwk, err = jwt.GetJSONWebKey(ctx, &jwt.GetJSONWebKeyParams{
			KeyID:      unsafeClaims.KeyID,
			JWKSClient: v.jwksClient,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("verify-clerk: cannot retrieve instance jwt keys: %w", err)
		}
		v.mx.Lock()
		v.keys[unsafeClaims.KeyID] = jwk
		v.mx.Unlock()
	}

	params := &jwt.VerifyParams{
		Token:                   token,
		JWK:                     jwk,
		CustomClaimsConstructor: func(_ context.Context) any { return new(CustomClaims) },
	}
	claims, err := jwt.Verify(ctx, params)
	if err != nil {
		return nil, nil, fmt.Errorf("verify-clerk: cannot verify token: %w", err)
	}
	return claims, claims.Custom.(*CustomClaims), nil
}
