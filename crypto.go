package crypto

// Number2BytesInNetworkOrder 将一个数字转换成生成4个字节的网络字节序bytes数组
func Number2BytesInNetworkOrder(number int) []byte {
	orderBytes := make([]byte, 4)
	orderBytes[3] = byte(number & 0xFF)
	orderBytes[2] = byte(number >> 8 & 0xFF)
	orderBytes[1] = byte(number >> 16 & 0xFF)
	orderBytes[0] = byte(number >> 24 & 0xFF)
	return orderBytes
}

// BytesNetworkOrder2Number 4个字节的网络字节序bytes数组还原成一个数字
func BytesNetworkOrder2Number(bytesInNetworkOrder []byte) int {
	sourceNumber := 0
	for i := 0; i < 4; i++ {
		sourceNumber <<= 8
		sourceNumber |= int(bytesInNetworkOrder[i]) & 0xFF
	}
	return sourceNumber
}
