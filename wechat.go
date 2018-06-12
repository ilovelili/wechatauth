package wechatauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

const (
	wechatAuthorizeCodeURI = "https://open.weixin.qq.com/connect/qrconnect"
	wechatAccessTokenURI   = "https://api.weixin.qq.com/sns/oauth2/access_token"
	wechatRefreshTokenURI  = "https://api.weixin.qq.com/sns/oauth2/refresh_token"
	wechatUserInfoURI      = "https://api.weixin.qq.com/sns/userinfo"
)

type (
	// OAuthWeChat wechat oauth entity
	OAuthWeChat struct {
		OAuth
	}

	// WeChatAccessTokenResponse token response
	WeChatAccessTokenResponse struct {
		ErrCode      string `form:"errcode" json:"errcode"`
		ErrMsg       string `form:"errmsg" json:"errmsg"`
		OpenID       string `form:"openid" json:"openid"`
		UnionID      string `form:"unionid" json:"unionid"`
		AccessToken  string `form:"access_token" json:"access_token"`
		RefreshToken string `form:"refresh_token" json:"refresh_token"`
		ExpiresIn    int    `form:"expires_in" json:"expires_in"`
		Scope        string `form:"scope" json:"scope"`
	}

	// WeChatUserInfoResponse user info response
	WeChatUserInfoResponse struct {
		ErrCode    string   `form:"errcode" json:"errcode"`
		ErrMsg     string   `form:"errmsg" json:"errmsg"`
		OpenID     string   `form:"openid" json:"openid"`
		UnionID    string   `form:"unionid" json:"unionid"`
		Nickname   string   `form:"nickname" json:"nickname"`
		HeadImgURI string   `form:"headimgurl" json:"headimgurl"`
		Sex        int      `form:"sex" json:"sex"` //1: male 2: female
		Country    string   `form:"country" json:"country"`
		Province   string   `form:"province" json:"province"`
		City       string   `form:"city" json:"city"`
		Privileges []string `form:"privilege" json:"privilege"`
	}
)

// NewWeChat init
func NewWeChat(clientID, clientSecret, callbackURI string) OAuther {
	oauth := new(OAuthWeChat)
	oauth.ClientID = clientID
	oauth.ClientSecret = clientSecret
	oauth.CallbackURI = callbackURI

	oauth.AuthorizeCodeURI = wechatAuthorizeCodeURI
	oauth.AccessTokenURI = wechatAccessTokenURI
	oauth.RefreshTokenURI = wechatRefreshTokenURI
	oauth.UserInfoURI = wechatUserInfoURI
	return oauth
}

// SetURI OAuther SetURI implementation
func (s *OAuthWeChat) SetURI(uriType OAuthURIType, uri string) {
	switch uriType {
	case AuthorizeCodeURI:
		s.AuthorizeCodeURI = uri
	case AccessTokenURI:
		s.AccessTokenURI = uri
	case RefreshTokenURI:
		s.RefreshTokenURI = uri
	case UserInfoURI:
		s.UserInfoURI = uri
	}
}

// GetAuthorizeURI OAuther GetAuthorizeURI implementation
func (s *OAuthWeChat) GetAuthorizeURI(args ...string) string {
	state, scope := "wechat", "snsapi_login"

	argCount := len(args)
	if argCount > 0 {
		state = args[0]

		if argCount > 1 {
			scope = args[1]
		}
	}

	params := map[string]interface{}{
		"appid":         s.ClientID,
		"redirect_uri":  queryEscape(s.CallbackURI),
		"scope":         scope,
		"state":         state,
		"response_type": "code",
	}

	queryString := toQueryString(params)
	return s.AuthorizeCodeURI + "?" + queryString
}

/*
 * GetAccessToken
 * {
 * "access_token":"ACCESS_TOKEN",
 * "expires_in":7200,
 * "refresh_token":"REFRESH_TOKEN",
 * "openid":"OPENID",
 * "scope":"SCOPE"
 * }
 */
func (s *OAuthWeChat) GetAccessToken(code string) (*OAuthToken, error) {
	var oauthToken *OAuthToken

	params := map[string]interface{}{
		"appid":      s.ClientID,
		"secret":     s.ClientSecret,
		"code":       code,
		"grant_type": "authorization_code",
	}
	queryString := toQueryString(params)

	// call apu
	resp, err := httpGet(s.AccessTokenURI, queryString)
	if err == nil {
		// parse json
		var tokenResponse *WeChatAccessTokenResponse
		fromJSON(resp, &tokenResponse)

		if tokenResponse != nil {
			oauthToken = &OAuthToken{
				AccessToken:  tokenResponse.AccessToken,
				RefreshToken: tokenResponse.RefreshToken,
				OpenID:       tokenResponse.OpenID,
				UnionID:      tokenResponse.UnionID,
				Scope:        tokenResponse.Scope,
				ExpiresIn:    tokenResponse.ExpiresIn,
			}

			return oauthToken, nil
		}
	}

	return nil, err
}

/* {
 * "access_token":"ACCESS_TOKEN",
 * "expires_in":7200,
 * "refresh_token":"REFRESH_TOKEN",
 * "openid":"OPENID",
 * "scope":"SCOPE"
 * }
 */
func (s *OAuthWeChat) RefreshAccessToken(refreshToken string) (*OAuthToken, error) {
	var oauthToken *OAuthToken

	params := map[string]interface{}{
		"appid":         s.ClientID,
		"refresh_token": refreshToken,
		"grant_type":    "refresh_token",
	}

	queryString := toQueryString(params)

	// call wechat API
	resp, err := httpGet(s.RefreshTokenURI, queryString)
	if err == nil {
		// parse json
		var tokenResponse *WeChatAccessTokenResponse
		fromJSON(resp, &tokenResponse)

		if tokenResponse != nil {
			oauthToken = &OAuthToken{
				AccessToken:  tokenResponse.AccessToken,
				RefreshToken: tokenResponse.RefreshToken,
				OpenID:       tokenResponse.OpenID,
				Scope:        tokenResponse.Scope,
				ExpiresIn:    tokenResponse.ExpiresIn,
			}
		}
		return oauthToken, nil
	}

	return nil, err
}

/*
 * {
 * "openid":"OPENID",
 * "nickname":"NICKNAME",
 * "sex":1,
 * "province":"PROVINCE",
 * "city":"CITY",
 * "country":"COUNTRY",
 * "headimgurl": "http://wx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/0",
 * "privilege":[
 * "PRIVILEGE1",
 * "PRIVILEGE2"
 * ],
 * "unionid": " o6_bmasdasdsad6_2sgVt7hMZOPfL"
 * }
 */
func (s *OAuthWeChat) GetUserInfo(accessToken, openID string) (*OAuthUser, error) {
	var oauthUser *OAuthUser
	params := map[string]interface{}{
		"access_token": accessToken,
		"openid":       openID,
		"lang":         "zh-CN", // hardcode
	}
	queryString := toQueryString(params)

	// call wechat API
	resp, err := httpGet(s.UserInfoURI, queryString)
	if err == nil {
		var userInfoResponse *WeChatUserInfoResponse

		//解析json数据
		fromJSON(resp, &userInfoResponse)

		if userInfoResponse != nil {
			sexCode := "secret"
			if userInfoResponse.Sex == 1 {
				sexCode = "m"
			} else if userInfoResponse.Sex == 2 {
				sexCode = "f"
			}
			oauthUser = &OAuthUser{
				Nickname: userInfoResponse.Nickname,
				Avatar:   userInfoResponse.HeadImgURI,
				Sex:      sexCode,
				Token: &OAuthToken{
					UnionID: userInfoResponse.UnionID,
				},
			}
		}
	}

	return oauthUser, err
}

// toQueryString a simple querystring wrapper
func toQueryString(values map[string]interface{}, args ...bool) string {
	isEncode := false
	queryString := ""

	if len(args) > 0 {
		isEncode = args[0]
	}

	for k, v := range values {
		if isEncode {
			v = queryEscape(fmt.Sprintf("%v", v))
		}
		queryString = queryString + fmt.Sprintf("%s=%v&", k, v)
	}
	queryString = queryString[0 : len(queryString)-1]

	return queryString
}

// queryEscape query escape wrapper
func queryEscape(value string) string {
	encodeValue := value
	if value != "" {
		encodeValue = url.QueryEscape(value)
	}

	return encodeValue
}

func httpGet(url string, args ...string) (string, error) {
	requestURL := url
	if len(args) == 1 {
		params := args[0]
		requestURL = fmt.Sprintf("%s?%s", url, params)
	}

	resp, err := http.Get(requestURL)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func toJSON(object interface{}) (string, error) {
	v, err := json.Marshal(object)
	if err != nil {
		return "", err
	}

	return string(v), nil
}

func fromJSON(jsonString string, object interface{}) error {
	bytesData := []byte(jsonString)
	return json.Unmarshal(bytesData, object)
}
