package aliyun_test

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suisrc/crypto.zgo/aliyun"
)

func TestSign(t *testing.T) {
	str := "POS"
	sig := aliyun.Sign(str, "AS", "&")

	log.Println(sig)

	assert.NotNil(t, nil)

}
