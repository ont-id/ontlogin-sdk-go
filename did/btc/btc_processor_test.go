package btc

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/test-go/testify/assert"
	"testing"
)

func TestBTCVerifySig(t *testing.T) {
	nbp := NewBtcProcessor()

	//pubKeyBytes, _ := hex.DecodeString("02a673638cb9587cb68ea08dbef685c6f2d2a751a8b3c6f2a7e9a4999e6e4bfaf5")
	//sigBytes, _ := hex.DecodeString("30450220090ebfb3690a0ff115bb1b38b8b323a667b7653454f1bccb06d4bbdca42c2079022100ec95778b51e707" +
	//	"1cb1205f8bde9af6592fc978b0452dafe599481c46d6b2e479")
	//message := "test message"
	//bo := nbp.VerifySig("", 0, []byte(message), sigBytes, pubKeyBytes)
	//assert.Nil(t, bo)

	pubKeyBytes, _ := hex.DecodeString("026887958bcc4cb6f8c04ea49260f0d10e312c41baf485252953b14724db552aac")
	sigBytes, err := base64.StdEncoding.DecodeString("G6nd7IqQaU8kxNbUDCnGLf+lA5ZxJ9TVlNOoNSuQ6j1yD1lG/Y25h01yT7SNxW56IuGNRX8Eu4baQYzhU78Wa0o=")
	assert.Nil(t, err)
	message := "hello world~"
	err = nbp.VerifySig("", 0, []byte(message), sigBytes, pubKeyBytes)
	assert.Nil(t, err)
}
