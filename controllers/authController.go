package controllers

import (
	"encoding/json"
	"go-rest-api/models"
	utils "go-rest-api/utils"
	"net/http"
)

var CreateAccount = func(w http.ResponseWriter, r *http.Request) {

	account := &models.Account{}
	err := json.NewDecoder(r.Body).Decode(account)
	if err != nil {
		utils.Respond(w, utils.Message(false, "Geçersiz istek. Lütfen kontrol ediniz!"))
		return
	}

	resp := account.Create()
	utils.Respond(w, resp)
}

var Authenticate = func(w http.ResponseWriter, r *http.Request) {

	account := &models.Account{}
	err := json.NewDecoder(r.Body).Decode(account)
	if err != nil {
		utils.Respond(w, utils.Message(false, "Geçersiz istek. Lütfen kontrol ediniz!"))
		return
	}

	resp := models.Login(account.Email, account.Password)
	utils.Respond(w, resp)
}
