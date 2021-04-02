package weixin_test

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suisrc/crypto.zgo/weixin"
)

func TestWxCrypto2(t *testing.T) {
	// wc := WxNewCrypto("123456", "IDKxiddis98", RandomAes32())
	wc := weixin.NewCrypto2("123456", "IDKxiddis98", "lBXYSlGJuQcFPiS4KCfLGxQjmcHJRrJuoIfrKC2NPwt")
	log.Println(wc.EncodingAesKey)

	text := "你好, golang, {}, IDixudDLSOCKSIcskDI, DNIs /slo ////*sd*(<xml?>"
	etext, err := wc.Encrypt(text)
	assert.Nil(t, err)
	log.Println(etext)

	utext, err := wc.Decrypt(etext)
	assert.Nil(t, err)
	log.Println(utext)

}
