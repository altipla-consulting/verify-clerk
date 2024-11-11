package clerk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/clerk/clerk-sdk-go/v2/jwks"
	"github.com/clerk/clerk-sdk-go/v2/jwt"
	"github.com/clerk/clerk-sdk-go/v2/user"
)

type Verifier[CustomClaims any] struct {
	mx   sync.RWMutex
	keys map[string]*clerk.JSONWebKey

	aud         Audience
	jwksClient  *jwks.Client
	clerkClient *user.Client
}

type Audience struct {
	v string
}

func ExpectedAudience(aud string) Audience {
	return Audience{v: aud}
}

func NewVerifier[CustomClaims any](apiKey string, aud Audience) *Verifier[CustomClaims] {
	if apiKey == "" {
		panic("verify-clerk: missing Clerk API key")
	}
	if aud.v == "" {
		panic("verify-clerk: missing expected audience")
	}

	config := &clerk.ClientConfig{
		BackendConfig: clerk.BackendConfig{
			Key: clerk.String(apiKey),
		},
	}
	return &Verifier[CustomClaims]{
		keys:        make(map[string]*clerk.JSONWebKey),
		aud:         aud,
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
		jwk, err = v.fetchJSONWebKey(ctx, unsafeClaims.KeyID)
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

	if !slices.Contains(claims.Audience, v.aud.v) {
		return nil, nil, fmt.Errorf("verify-clerk: audience %q missing in %v", v.aud.v, claims.Audience)
	}

	return claims, claims.Custom.(*CustomClaims), nil
}

func (v *Verifier[CustomClaims]) fetchJSONWebKey(ctx context.Context, keyID string) (*clerk.JSONWebKey, error) {
	var jwk *clerk.JSONWebKey
	var err error

	for i := 0; i < 3; i++ {
		jwk, err = jwt.GetJSONWebKey(ctx, &jwt.GetJSONWebKeyParams{
			KeyID:      keyID,
			JWKSClient: v.jwksClient,
		})
		if err == nil {
			return jwk, nil
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		} else {
			return nil, err
		}
	}

	return nil, err
}
