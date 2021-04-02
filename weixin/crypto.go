package weixin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"sort"

	"github.com/suisrc/crypto.zgo"
)

/**
 * 对公众平台发送给公众账号的消息加解密示例代码.
 * 提供基于PKCS7算法的加解
 */
const (
	blockSize = 32
)

// PKCS7Encode 获得对明文进行补位填充的字节.
// param count 需要进行填充补位操作的明文字节个数
// return 补齐用的字节数组
func PKCS7Encode(count int) []byte {
	// 计算需要填充的位数
	amountToPad := blockSize - (count % blockSize)
	if amountToPad == 0 {
		amountToPad = blockSize
	}
	// 获得补位所用的字符
	// 将数字转化成ASCII码对应的字符，用于对明文进行补码
	padChr := rune(amountToPad & 0xFF)
	var tmp bytes.Buffer
	for index := 0; index < amountToPad; index++ {
		tmp.WriteRune(padChr)
	}
	return tmp.Bytes()
}

// PKCS7Decode 删除解密后明文的补位字符
// param decrypted 解密后的明文
// return 删除补位字符后的明文
func PKCS7Decode(decrypted []byte) []byte {
	pad := decrypted[len(decrypted)-1]
	if pad < 1 || pad > blockSize {
		pad = 0
	}
	return decrypted[:len(decrypted)-int(pad)]
}

// NewCrypto 注意,来自微信的AesKey需要增加一个"="符号,推荐使用WxNewCrypto2处理
func NewCrypto(appid, token, encodingAesKey string) *WxCrypto {
	// 必须使用RFC2045标准执行解密
	aesKey, err := crypto.Base64DecodeString(encodingAesKey)
	if err != nil {
		panic(err)
	}
	return &WxCrypto{
		AesKey:         aesKey,
		Token:          token,
		AppID:          appid,
		EncodingAesKey: encodingAesKey,
	}
}

// WxNewCrypto2 new
func NewCrypto2(appid, token, encodingAesKey string) *WxCrypto {
	return NewCrypto(appid, token, encodingAesKey+"=")
}

// Encrypt 对明文进行加密
// param plainText 需要加密的明文
// return 加密后base64编码的字符串
func (a *WxCrypto) Encrypt(plainText string) (string, error) {
	randomStr := crypto.UUID2(16)

	randomStringBytes := []byte(randomStr)
	plainTextBytes := []byte(plainText)
	bytesOfSizeInNetworkOrder := crypto.Number2BytesInNetworkOrder(len(plainTextBytes))
	appIDBytes := []byte(a.AppID)

	var byteCollector bytes.Buffer

	// randomStr + networkBytesOrder + text + appid
	byteCollector.Write(randomStringBytes)
	byteCollector.Write(bytesOfSizeInNetworkOrder)
	byteCollector.Write(plainTextBytes)
	byteCollector.Write(appIDBytes)

	// ... + pad: 使用自定义的填充方式对明文进行补位填充
	padBytes := PKCS7Encode(byteCollector.Len())
	byteCollector.Write(padBytes)

	// 获得最终的字节流, 未加密
	unencrypted := byteCollector.Bytes()

	//create aes
	cip, err := aes.NewCipher(a.AesKey)
	if err != nil {
		return "", err
	}
	//log.Println(cip.BlockSize())
	//encrypt string
	cbc := cipher.NewCBCEncrypter(cip, a.AesKey[:cip.BlockSize()])
	encrypted := make([]byte, len(unencrypted))
	cbc.CryptBlocks(encrypted, unencrypted)

	cipherText := crypto.Base64EncodeToString(encrypted)
	return cipherText, nil
}

// Decrypt 对密文进行解密.
// param cipherText 需要解密的密文
// return 解密得到的明文
func (a *WxCrypto) Decrypt(cipherText string) (string, error) {
	return a.DecryptCheckAppID(cipherText, nil)
}

// DecryptCheckAppID 对密文进行解密.
// param cipherText 需要解密的密文
// param appidOrCorpid 获取解密内容回调，如果为空，会强制判断该内容是否和加密器中的ID相同
// return 解密得到的明文
func (a *WxCrypto) DecryptCheckAppID(cipherText string, appIDCheck func(string) error) (string, error) {
	if cipherText == "" {
		return "", nil
	}
	cip, err := aes.NewCipher(a.AesKey)
	if err != nil {
		return "", err
	}
	encrypted, err := crypto.Base64DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	// CBC mode always works in whole blocks.
	if len(encrypted)%blockSize != 0 {
		return "", errors.New("cipherText is not a multiple of the block size")
	}
	//encrypt string
	cbc := cipher.NewCBCDecrypter(cip, a.AesKey[:cip.BlockSize()])
	unencrypted := make([]byte, len(encrypted))
	cbc.CryptBlocks(unencrypted, encrypted)

	// 去除补位字符
	content := PKCS7Decode(unencrypted)
	// 分离16位随机字符串,网络字节序和AppId
	networkOrder := content[16:20]
	plainTextLen := crypto.BytesNetworkOrder2Number(networkOrder)

	appIDBytes := content[20+plainTextLen:]
	appID := string(appIDBytes)

	if appIDCheck != nil {
		if err := appIDCheck(appID); err != nil {
			return "", err
		}
	} else if appID != a.AppID {
		//return "", fmt.Errorf("AppID Error: %s -> %s", appID, a.AppID)
		return "", errors.New("AppID Error")
	}

	plainTextBytes := content[20 : 20+plainTextLen]
	plainText := string(plainTextBytes)
	return plainText, nil
}

// GenSHA1 排序,串接arr参数，生成sha1 digest
func GenSHA1(arr ...string) string {
	if len(arr) == 0 {
		return ""
	}
	strs := make([]string, len(arr))
	copy(strs, arr)

	var builder bytes.Buffer
	sort.Strings(strs)
	for _, v := range strs {
		builder.WriteString(v)
	}

	// return builder.String()
	return crypto.SHA1Hash(builder.Bytes())
}

// GenSHA1And 排序,串接arr参数，生成sha1 digest
func GenSHA1And(arr ...string) string {
	if len(arr) == 0 {
		return ""
	}
	strs := make([]string, len(arr))
	copy(strs, arr)
	sort.Strings(strs)

	var builder bytes.Buffer
	for _, v := range strs {
		if builder.Len() > 0 {
			builder.WriteByte('&')
		}
		builder.WriteString(v)
	}

	// return builder.String()
	return crypto.SHA1Hash(builder.Bytes())
}

// GenMD5 排序，加密, 用于红包数据签名
func GenMD5(datas map[string]string, sign string) string {
	// keys := reflect.ValueOf(datas).MapKeys()
	keys := make([]string, len(datas))
	for k := range datas {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var builder bytes.Buffer
	for _, k := range keys {
		builder.WriteString(k)
		builder.WriteByte('=')
		builder.WriteString(datas[k])
		builder.WriteByte('&')
	}
	builder.WriteString("key=")
	builder.WriteString(sign)

	// return builder.String()
	return crypto.SHA1Hash(builder.Bytes())
}
