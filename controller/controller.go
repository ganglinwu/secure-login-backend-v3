package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ganglinwu/secure-login-v3/errs"
	"github.com/ganglinwu/secure-login-v3/models"
	jsonWebTokes "github.com/ganglinwu/secure-login-v3/utils"
)

type UserStore interface {
	RegisterNewUser(models.ServerUser) error
	FetchUser(string) (*models.ServerUser, error)
	UpdateUser(string, string) error
	RemoveUser(models.ServerUser) error
	Login(models.ClientUser) error
}

type LoginServer struct {
	store UserStore
	http.Handler
}

// Create new server
func NewLoginServer(store UserStore) *LoginServer {
	server := LoginServer{}
	server.store = store

	r := http.NewServeMux()

	r.HandleFunc("POST /", server.HandleRegistration)
	r.HandleFunc("POST /users", server.HandleFetchUser)
	r.HandleFunc("POST /delete-user", server.HandleDeleteUser)
	r.HandleFunc("POST /update-user", server.HandleUpdateUser)
	r.HandleFunc("POST /login", server.HandleLogin)

	server.Handler = r

	return &server
}

/*
*
*  HANDLER FUNCTIONS (START)
*
 */

func (s *LoginServer) HandleRegistration(w http.ResponseWriter, r *http.Request) {
	// CHECK: form exists and usable on our end
	// Possible errors: too many
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, err.Error())
		return
	}

	// CHECK: email not blank
	email := r.FormValue("Email")
	if email == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errs.EmailIsBlank.Error())
		return
	}
	// CHECK: password not blank
	password := r.FormValue("Password")
	if password == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errs.PasswordIsBlank.Error())
		return
	}

	// hash and check error
	// Possible errors: password too long, cost is out of bounds
	byteHashedPW, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		if len(password) > 72 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, err.Error())
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err.Error())
		return
	}
	// check if user email is already registered
	// first we search store for user
	a, err := s.store.FetchUser(email)
	// if error, something wrong with searching
	if err != nil {
		if err == errs.UserNotFound {
			// do nothing and continue
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	// if user found, then cannot register with this email
	if a != nil {
		http.Error(w, errs.UserAlreadyExists.Error(), http.StatusBadRequest)
	}

	// calling store method RegisterNewUser
	err = s.store.RegisterNewUser(models.ServerUser{Email: email, HPassword: string(byteHashedPW)})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Bad request")
		return
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Successfully registered user with email: %s", email)
}

func (s *LoginServer) HandleFetchUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, err.Error())
		return
	}

	email := r.FormValue("Email")
	if email == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errs.EmailIsBlank.Error())
		return
	}

	user, err := s.store.FetchUser(email)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, err.Error())
		return
	}

	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "error marshalling user to json")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *LoginServer) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, err.Error())
		return
	}

	// CHECK: email not blank
	email := r.FormValue("Email")
	if email == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errs.EmailIsBlank.Error())
		return
	}
	// CHECK: password not blank
	password := r.FormValue("Password")
	if password == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errs.PasswordIsBlank.Error())
		return
	}

	existingUser, err := s.store.FetchUser(email)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errs.UserNotFound.Error())
		return
	}

	user := models.ServerUser{}

	user.Email = email
	err = bcrypt.CompareHashAndPassword([]byte(existingUser.HPassword), []byte(password))
	if err != nil { // password does not match
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, err.Error())
		return
	} else {
		err = s.store.RemoveUser(user)
	}

	switch err {
	case nil:
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Successfully deleted user with email:", email)
		return

	default:
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, err.Error())
		return
	}
}

func (s *LoginServer) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, err.Error())
		return
	}

	// check new email blank
	newUserEmail := r.FormValue("Email")
	if newUserEmail == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errs.EmailIsBlank.Error())
		return
	}

	/*
	*
	* End of Form Parsing
	* Below we get user name from JWT token in cookie
	*
	 */
	jwtCookie, err := r.Cookie("jwt")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "not authorized, please log in. err: %s", err.Error())
		return
	}

	currentUserEmail, err := jsonWebTokes.CheckAuthToken(jwtCookie.Value)

	// check new with current email
	if newUserEmail == currentUserEmail {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "email to be updated is the same as current email, abort update")
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "unauthorized 2, please log in again")
		return
	} else {
		err = s.store.UpdateUser(currentUserEmail, newUserEmail)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "bad request: %s\n", err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "update success")
	}
}

func (s *LoginServer) HandleLogin(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, err.Error())
		return
	}

	// CHECK: email not blank
	email := r.FormValue("Email")
	if email == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errs.EmailIsBlank.Error())
		return
	}
	// CHECK: password not blank
	password := r.FormValue("Password")
	if password == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, errs.PasswordIsBlank.Error())
		return
	}

	user := models.ClientUser{}

	user.Email = email
	user.Password = password

	err = s.store.Login(user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "failed to login")
		return
	} else {
		token, err := jsonWebTokes.GenAuthToken(email)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "failed to generate jwt token: %s", err.Error())
			return
		}
		cookie := http.Cookie{
			Name:     "jwt",
			Value:    token,
			Expires:  time.Now().Add(5 * time.Minute),
			HttpOnly: true,
		}
		http.SetCookie(w, &cookie)
		w.WriteHeader(http.StatusOK)
		return
	}
}

/*
*
*  HANDLER FUNCTIONS (END)
*
 */
