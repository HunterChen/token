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

type Token struct {
	Id         string
	Expiration int64
	Signature  string
}

type TokenError struct {
	Message string
	Details error
}

var hash = crypto.SHA256

func CreateToken(key *rsa.PrivateKey, id string) (*Token, *TokenError) {
	expiration := time.Now().Add(time.Hour + tokenDuration).Unix()

	encodeParams := makeEncodeParams(id, expiration)

	if !hash.Available() {
		return nil, &TokenError{"ハッシュの初期化に失敗しました", nil}
	}

	hs := hash.New()
	hs.Write([]byte(encodeParams))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, hash, hs.Sum(nil))
	if err != nil {
		return nil, &TokenError{"シグネチャの生成に失敗しました", err}
	}

	return &Token{id, expiration, encode(signature)}, nil
}

func ParseToken(tokenString string) (*Token, *TokenError) {
	parts := strings.Split(tokenString, ".")

	if len(parts) != 2 {
		return nil, &TokenError{"Tokenが不正です", nil}
	}

	decodeParams, err := decode(parts[0])
	if err != nil {
		return nil, &TokenError{"パラメータのデコードに失敗しました", err}
	}

	var params map[string]interface{}

	decoder := json.NewDecoder(bytes.NewBuffer(decodeParams))
	decoder.UseNumber()
	if err := decoder.Decode(&params); err != nil {
		return nil, &TokenError{"不明なエラー", err}
	}

	id, ok := params["Id"].(string)
	if !ok {
		return nil, &TokenError{"Idが不正です", nil}
	}

	exNum, ok := params["Expiration"].(json.Number)
	if !ok {
		return nil, &TokenError{"Expirationが不正です", nil}
	}

	expiration, err := exNum.Int64()
	if err != nil {
		return nil, &TokenError{"不明なエラー", err}
	}

	return &Token{id, expiration, parts[1]}, nil
}

func (t *Token) GetTokenString() string {
	var parts [2]string

	parts[0] = makeEncodeParams(t.Id, t.Expiration)
	parts[1] = t.Signature

	return strings.Join(parts[:], ".")
}

func (t *Token) IsValid(key *rsa.PublicKey) *TokenError {
	signatureBytes, err := decode(t.Signature)
	if err != nil {
		return &TokenError{"Tokenが不正です", err}
	}

	now := time.Now().Unix()

	if t.Expiration < now {
		return &TokenError{"Tokenの期限が切れています", nil}
	}

	encodeParams := makeEncodeParams(t.Id, t.Expiration)

	if !hash.Available() {
		return &TokenError{"ハッシュの初期化に失敗しました", nil}
	}

	hs := hash.New()
	hs.Write([]byte(encodeParams))

	if err := rsa.VerifyPKCS1v15(key, hash, hs.Sum(nil), signatureBytes); err != nil {
		return &TokenError{"シグネチャが不正です", err}
	}

	return nil
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
