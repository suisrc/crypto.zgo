package weixin

// WxCrypto wechat 加密
type WxCrypto struct {
	AesKey         []byte
	Token          string
	AppID          string
	EncodingAesKey string
}

// WxSignature signature
type WxSignature struct {
	Signature string `form:"signature"`
	Timestamp string `form:"timestamp"`
	Nonce     string `form:"nonce"`
	Echostr   string `form:"echostr"`
}

// WxEncryptSignature jsapi signature
type WxEncryptSignature struct {
	WxSignature
	MsgSignature string `form:"msg_signature"`
	EncryptType  string `form:"encrypt_type"`
}

// WxEncryptMessage 加密文件存储
type WxEncryptMessage struct {
	ToUserName   string `json:",omitempty"` // ToUserName为公众号AppId或者企业号的CorpID
	AgentID      string `json:",omitempty"` // 为接收的应用id，可在应用的设置页面获取 只有企业号，该字段才有值
	Encrypt      string `json:",omitempty"` // 密文 encrypt为经过加密的密文（消息明文格式参见 接收普通消息，事件明文格式参见 接收事件）
	MsgSignature string `json:",omitempty"` // 密文签名
	TimeStamp    string `json:",omitempty"` // 密文时间戳
	Nonce        string `json:",omitempty"` // 密文随机码
}

// WxAccessToken access token
type WxAccessToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   string `json:"expires_in"`
}
