package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ganglinwu/secure-login-v3/errs"
	"github.com/ganglinwu/secure-login-v3/models"
	"golang.org/x/crypto/bcrypt"
)

// --------------- BEGIN mockStore -----------------------
type mockStore struct {
	store []models.ServerUser
}

func (m *mockStore) RegisterNewUser(user models.ServerUser) error {
	if user.Email != "" && user.HPassword != "" {
		for _, u := range m.store {
			if u.Email == user.Email {
				return errs.UserAlreadyExists
			}
		}
		m.store = append(m.store, user)
		return nil
	} else {
		return errors.New("blank fields")
	}
}

func (m *mockStore) FetchUser(email string) (*models.ServerUser, error) {
	if len(m.store) == 0 {
		return nil, errs.UserNotFound
	}
	for _, user := range m.store {
		if user.Email == email {
			return &user, nil
		}
	}
	return nil, errs.UserNotFound
}

func (m *mockStore) RemoveUser(clientUser models.ServerUser) error {
	if len(m.store) == 0 {
		return errs.UserNotFound
	}
	for i, user := range m.store {
		if user.Email == clientUser.Email {
			m.store = slices.Delete(m.store, i, i+1)
			return nil
		}
	}
	return errs.UserNotFound
}

func (m *mockStore) Login(user models.ClientUser) error {
	if len(m.store) == 0 {
		return errs.LoginFailed
	}
	for _, u := range m.store {
		if u.Email == user.Email {
			err := bcrypt.CompareHashAndPassword([]byte(u.HPassword), []byte(user.Password))
			if err != nil {
				return errs.LoginFailedBadPassword
			}
			return nil
		}
	}
	return errs.LoginFailed
}

// --------------- END mockStore -----------------------

var NewUser1 = models.ServerUser{
	Email:     "newuser@gmail.com",
	HPassword: "$2a$10$87jJGy8zixinAPj5AsZhcuUD0jEpDVS.Y3y1ctUUZU/Yc4mOxKAT6",
}

func TestRegisterNewUser(t *testing.T) {
	registerTests := []struct {
		testname       string
		user           models.ClientUser
		want           models.ServerUser
		wantStatusCode int
	}{
		{"register blank email", models.ClientUser{Email: "", Password: "hashed123"}, models.ServerUser{}, http.StatusBadRequest},
		{"register blank password", models.ClientUser{Email: "newuser@gmail.com", Password: ""}, models.ServerUser{}, http.StatusBadRequest},
		{"register NewUser1", models.ClientUser{Email: "newuser@gmail.com", Password: "hashed123"}, NewUser1, http.StatusCreated},
	}

	for _, test := range registerTests {
		fmt.Println("running test:", test.testname)
		data := url.Values{
			"Email":    {test.user.Email},
			"Password": {test.user.Password},
		}
		body := strings.NewReader(data.Encode())
		req, _ := http.NewRequest(http.MethodPost, "/", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resRec := httptest.NewRecorder()

		ms := mockStore{}
		s := NewLoginServer(&ms)

		s.ServeHTTP(resRec, req)

		want := test.want

		got := models.ServerUser{}

		if len(ms.store) == 0 {
			// if nothing found
			// then do nothing and proceed to compare status code
		} else {
			for _, user := range ms.store {
				if user.Email == want.Email {
					got = user
					// since user is found, then the email is already matched
					// only need to compare hashed pw next
					err := bcrypt.CompareHashAndPassword([]byte(got.HPassword), []byte("hashed123"))
					if err != nil {
						t.Errorf("got %q, want %q", got.HPassword, want.HPassword)
					}
				}
			}
			// in case we were expecting an entry but didm't get one
			if got.Email != want.Email {
				t.Errorf("got %q, want %q", got.Email, want.Email)
			}
		}

		if resRec.Code != test.wantStatusCode {
			t.Errorf("got status code %d, want status code %d", resRec.Code, test.wantStatusCode)
		}
	}
}

func TestFetchUser(t *testing.T) {
	fetchTests := []struct {
		name           string
		email          string
		store          mockStore
		want           models.ServerUser
		wantStatusCode int
	}{
		{"empty email", "", mockStore{[]models.ServerUser{NewUser1}}, models.ServerUser{}, http.StatusBadRequest},
		{"empty store", "newuser@gmail.com", mockStore{[]models.ServerUser{}}, models.ServerUser{}, http.StatusBadRequest},
		{"fetch user from store", "newuser@gmail.com", mockStore{[]models.ServerUser{NewUser1}}, NewUser1, http.StatusOK},
	}
	for _, test := range fetchTests {
		fmt.Println("running test:", test.name)

		clientData := url.Values{
			"Email": {test.email},
		}
		body := strings.NewReader(clientData.Encode())
		req, _ := http.NewRequest(http.MethodPost, "/users", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resRec := httptest.NewRecorder()

		ms := test.store
		s := NewLoginServer(&ms)

		s.ServeHTTP(resRec, req)

		response := resRec.Result()

		defer response.Body.Close()

		got := models.ServerUser{}
		if response.StatusCode == 200 {
			err := json.NewDecoder(resRec.Body).Decode(&got)
			if err != nil {
				t.Fatal(err)
			}
		}

		want := test.want

		if got.Email != want.Email {
			t.Errorf("got %q, want %q", got.Email, want.Email)
		}
		if response.StatusCode != test.wantStatusCode {
			t.Errorf("got status code %d, want status code %d", response.StatusCode, test.wantStatusCode)
		}
	}
}

func TestRemoveUser(t *testing.T) {
	deleteTests := []struct {
		name       string
		user       models.ClientUser
		store      mockStore
		wantErr    error
		wantStatus int
	}{
		{"empty email", models.ClientUser{Password: "hashed123"}, mockStore{[]models.ServerUser{NewUser1}}, errs.EmailIsBlank, http.StatusBadRequest},
		{"empty password", models.ClientUser{Email: "newuser@gmail.com", Password: ""}, mockStore{[]models.ServerUser{NewUser1}}, errs.PasswordIsBlank, http.StatusBadRequest},
		{"delete user from store", models.ClientUser{Email: "newuser@gmail.com", Password: "hashed123"}, mockStore{[]models.ServerUser{NewUser1}}, nil, http.StatusOK},
	}

	for _, test := range deleteTests {
		fmt.Println("running test:", test.name)
		clientData := url.Values{
			"Email":    {test.user.Email},
			"Password": {test.user.Password},
		}
		body := strings.NewReader(clientData.Encode())
		req, _ := http.NewRequest(http.MethodPost, "/delete-user", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resRec := httptest.NewRecorder()

		ms := test.store
		s := NewLoginServer(&ms)

		s.ServeHTTP(resRec, req)

		if resRec.Code != test.wantStatus {
			t.Errorf("got status code %d, want status code %d", resRec.Code, test.wantStatus)
		}
	}
}

func TestLogin(t *testing.T) {
	loginTests := []struct {
		name       string
		user       models.ClientUser
		store      mockStore
		wantStatus int
	}{
		{"empty email", models.ClientUser{Password: "hashed123"}, mockStore{[]models.ServerUser{NewUser1}}, http.StatusBadRequest},
		{"empty password", models.ClientUser{Email: "newuser@gmail.com"}, mockStore{[]models.ServerUser{NewUser1}}, http.StatusBadRequest},
		{"login user password", models.ClientUser{Email: "newuser@gmail.com", Password: "hashed123"}, mockStore{[]models.ServerUser{NewUser1}}, http.StatusOK},
		{"login user bad password", models.ClientUser{Email: "newuser@gmail.com", Password: "hashed321"}, mockStore{[]models.ServerUser{NewUser1}}, http.StatusBadRequest},
		{"login user does not exist", models.ClientUser{Email: "olduser@gmail.com", Password: "hashed321"}, mockStore{[]models.ServerUser{NewUser1}}, http.StatusBadRequest},
	}
	for _, test := range loginTests {
		fmt.Println("running test:", test.name)
		clientData := url.Values{
			"Email":    {test.user.Email},
			"Password": {test.user.Password},
		}
		body := strings.NewReader(clientData.Encode())
		req, _ := http.NewRequest(http.MethodPost, "/login", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resRec := httptest.NewRecorder()

		ms := test.store
		s := NewLoginServer(&ms)

		s.ServeHTTP(resRec, req)

		gotStatus := resRec.Code
		wantStatus := test.wantStatus

		if gotStatus != wantStatus {
			t.Errorf("got status code %d, want status code %d", gotStatus, wantStatus)
		}
	}
}
