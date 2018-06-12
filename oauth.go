package wechatauth

type (
	// OAuthURIType defines uri for oauth flow
	OAuthURIType int

	// OAuther oauth interface
	OAuther interface {
		SetURI(uriType OAuthURIType, uri string)
		GetAuthorizeURI(args ...string) string
		GetAccessToken(code string) (*OAuthToken, error)
		RefreshAccessToken(refreshToken string) (*OAuthToken, error)
		GetUserInfo(accessToken, openID string) (*OAuthUser, error)
	}

	// OAuth oauth entity
	OAuth struct {
		ClientID         string //app id
		ClientSecret     string //app secret
		CallbackURI      string
		AuthorizeCodeURI string
		AccessTokenURI   string
		RefreshTokenURI  string
		OpenIDURI        string
		UserInfoURI      string
	}

	// OAuthToken token entity
	OAuthToken struct {
		AccessToken  string
		RefreshToken string
		OpenID       string // some unique id of the user that could change from time to time
		UnionID      string // the unique id of the user, the only one that is always the same
		ExpiresIn    int
		Scope        string
	}

	// OAuthUser user entity
	OAuthUser struct {
		Avatar   string
		Nickname string
		Sex      string
		Year     string
		Province string
		City     string
		Token    *OAuthToken
	}
)

const (
	// AuthorizeCodeURI defines authorize code uri
	AuthorizeCodeURI OAuthURIType = iota
	// AccessTokenURI defines access token uri
	AccessTokenURI
	// RefreshTokenURI defines refresh token uri
	RefreshTokenURI
	// OpenIDURI defines openID uri
	OpenIDURI
	// UserInfoURI defines user info uri
	UserInfoURI
)
