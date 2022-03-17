package models

import (
	utils "go-rest-api/utils"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Token struct {
	UserId   uint
	Username string
	jwt.StandardClaims
}

type Account struct {
	gorm.Model
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token" sql:"-"`
}

func (account *Account) Validate() (map[string]interface{}, bool) {

	if !strings.Contains(account.Email, "@") {
		return utils.Message(false, "Email adresi hatalıdır!"), false
	}

	if len(account.Password) < 8 {
		return utils.Message(false, "Şifreniz en az 8 karakter olmalıdır!"), false
	}

	temp := &Account{}

	err := GetDB().Table("accounts").Where("email = ?", account.Email).First(temp).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return utils.Message(false, "Bağlantı hatası oluştutils. Lütfen tekrar deneyiniz!"), false
	}
	if temp.Email != "" {
		return utils.Message(false, "Email adresi başka bir kullanıcı tarafından kullanılıyor."), false
	}

	return utils.Message(false, "Her şey yolunda!"), true
}

func (account *Account) Create() map[string]interface{} {

	if resp, ok := account.Validate(); !ok {
		return resp
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	account.Password = string(hashedPassword)

	GetDB().Create(account)

	if account.ID <= 0 {
		return utils.Message(false, "Bağlantı hatası oluştutils. Kullanıcı yaratılamadı!")
	}

	tk := &Token{UserId: account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))
	account.Token = tokenString

	account.Password = ""

	response := utils.Message(true, "Hesap başarıyla yaratıldı!")
	response["account"] = account
	return response
}

func Login(email, password string) map[string]interface{} {

	account := &Account{}
	err := GetDB().Table("accounts").Where("email = ?", email).First(account).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return utils.Message(false, "Email adresi bulunamadı!")
		}
		return utils.Message(false, "Bağlantı hatası oluştutils. Lütfen tekrar deneyiniz!")
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		return utils.Message(false, "Parola hatalı! Lütfen tekrar deneyiniz!")
	}

	account.Password = ""

	tk := &Token{UserId: account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))
	account.Token = tokenString

	resp := utils.Message(true, "Giriş başarılı!")
	resp["account"] = account
	return resp
}
func GetUser(u uint) *Account {
	acc := &Account{}
	GetDB().Table("accounts").Where("id = ?", u).First(acc)
	if acc.Email == "" {
		return nil
	}

	acc.Password = ""
	return acc
}
