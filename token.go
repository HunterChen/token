package token

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const tokenDuration = 72

// Error is a model for token error
type Error struct {
	Message string
	Details error
}

// Token is a model for token
type Token struct {
	ID         string
	Expiration int64
	Signature  string
}

// GetTokenString is to get token string
func (t *Token) GetTokenString() string {
	var parts [2]string

	parts[0] = makeEncodeParams(t.ID, t.Expiration)
	parts[1] = t.Signature

	return strings.Join(parts[:], ".")
}

// IsValid is validates Token
func (t *Token) IsValid(key *rsa.PublicKey) *Error {
	signatureBytes, err := decode(t.Signature)
	if err != nil {
		return &Error{"Tokenが不正です", err}
	}

	now := time.Now().Unix()

	if t.Expiration < now {
		return &Error{"Tokenの期限が切れています", nil}
	}

	encodeParams := makeEncodeParams(t.ID, t.Expiration)

	if !hash.Available() {
		return &Error{"ハッシュの初期化に失敗しました", nil}
	}

	hs := hash.New()
	hs.Write([]byte(encodeParams))

	if err := rsa.VerifyPKCS1v15(key, hash, hs.Sum(nil), signatureBytes); err != nil {
		return &Error{"シグネチャが不正です", err}
	}

	return nil
}

var hash = crypto.SHA256

// CreateToken is to create a token
func CreateToken(key *rsa.PrivateKey, id string) (*Token, *Error) {
	expiration := time.Now().Add(time.Hour * tokenDuration).Unix()

	encodeParams := makeEncodeParams(id, expiration)

	if !hash.Available() {
		return nil, &Error{"ハッシュの初期化に失敗しました", nil}
	}

	hs := hash.New()
	hs.Write([]byte(encodeParams))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, hash, hs.Sum(nil))
	if err != nil {
		return nil, &Error{"シグネチャの生成に失敗しました", err}
	}

	return &Token{id, expiration, encode(signature)}, nil
}

// ParseToken is parse token string to token
func ParseToken(tokenString string) (*Token, *Error) {
	parts := strings.Split(tokenString, ".")

	if len(parts) != 2 {
		return nil, &Error{"Tokenが不正です", nil}
	}

	decodeParams, err := decode(parts[0])
	if err != nil {
		return nil, &Error{"パラメータのデコードに失敗しました", err}
	}

	var params map[string]interface{}

	decoder := json.NewDecoder(bytes.NewBuffer(decodeParams))
	decoder.UseNumber()
	if err := decoder.Decode(&params); err != nil {
		return nil, &Error{"不明なエラー", err}
	}

	id, ok := params["Id"].(string)
	if !ok {
		return nil, &Error{"Idが不正です", nil}
	}

	exNum, ok := params["Expiration"].(json.Number)
	if !ok {
		return nil, &Error{"Expirationが不正です", nil}
	}

	expiration, err := exNum.Int64()
	if err != nil {
		return nil, &Error{"不明なエラー", err}
	}

	return &Token{id, expiration, parts[1]}, nil
}

func makeEncodeParams(id string, expiration int64) string {
	params := map[string]interface{}{
		"Id":         id,
		"Expiration": expiration,
	}

	paramBytes, err := json.Marshal(params)
	if err != nil {
		return ""
	}

	return encode(paramBytes)
}

func encode(target []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(target), "=")
}

func decode(target string) ([]byte, error) {
	if l := len(target) % 4; 0 < l {
		target += strings.Repeat("=", 4-l)
	}

	result, err := base64.URLEncoding.DecodeString(target)
	if err != nil {
		return nil, err
	}

	return result, nil
}
