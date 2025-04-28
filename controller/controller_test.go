package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ganglinwu/secure-login-v3/errs"
	"github.com/ganglinwu/secure-login-v3/models"
	jsonWebTokes "github.com/ganglinwu/secure-login-v3/utils"
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

func (m *mockStore) UpdateUser(email string, newEmail string) error {
	newUser := models.ServerUser{}
	for i, user := range m.store {
		if user.Email == email {
			newUser.Email = newEmail
			newUser.HPassword = user.HPassword
			newUser.Created_at = user.Created_at
			newUser.Updated_at = time.Now()
			m.store = slices.Delete(m.store, i, i+1)
			m.store = append(m.store, newUser)
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

var (
	NewUser1 = models.ServerUser{
		Email:     "newuser@gmail.com",
		HPassword: "$2a$10$87jJGy8zixinAPj5AsZhcuUD0jEpDVS.Y3y1ctUUZU/Yc4mOxKAT6",
	}
	NewUser2 = models.ServerUser{
		Email:     "newuser2@gmail.com",
		HPassword: "$2a$10$kQ5icFIuyp/1vfocGKHh2eBn8hNVlrJtY40BWoHI99XnuY6t3gFXu",
	}
)

func TestRegisterNewUser(t *testing.T) {
	registerTests := []struct {
		testname       string
		user           models.ClientUser
		want           models.ServerUser
		wantStatusCode int
	}{
		{
			testname:       "register blank email",
			user:           models.ClientUser{Email: "", Password: "hashed123"},
			want:           models.ServerUser{},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			testname:       "register blank password",
			user:           models.ClientUser{Email: "newuser@gmail.com", Password: ""},
			want:           models.ServerUser{},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			testname:       "register NewUser1",
			user:           models.ClientUser{Email: "newuser@gmail.com", Password: "hashed123"},
			want:           NewUser1,
			wantStatusCode: http.StatusCreated,
		},
		{
			testname:       "register existing user NewUser2, expect bad request",
			user:           models.ClientUser{Email: "newuser2@gmail.com", Password: "NewUser2"},
			want:           models.ServerUser{},
			wantStatusCode: http.StatusBadRequest,
		},
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

		ms := mockStore{[]models.ServerUser{NewUser2}}
		s := NewLoginServer(&ms)

		s.ServeHTTP(resRec, req)

		want := test.want

		got := models.ServerUser{}

		// check if user successfully registered and persisted in store
		// if store is empty it could have been unsuccessful registration
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
		{
			name:           "empty email",
			email:          "",
			store:          mockStore{[]models.ServerUser{NewUser1}},
			want:           models.ServerUser{},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "empty store",
			email:          "newuser@gmail.com",
			store:          mockStore{[]models.ServerUser{}},
			want:           models.ServerUser{},
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "fetch user from store",
			email:          "newuser@gmail.com",
			store:          mockStore{[]models.ServerUser{NewUser1}},
			want:           NewUser1,
			wantStatusCode: http.StatusOK,
		},
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
		{
			name:       "empty email",
			user:       models.ClientUser{Password: "hashed123"},
			store:      mockStore{[]models.ServerUser{NewUser1}},
			wantErr:    errs.EmailIsBlank,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty password",
			user:       models.ClientUser{Email: "newuser@gmail.com", Password: ""},
			store:      mockStore{[]models.ServerUser{NewUser1}},
			wantErr:    errs.PasswordIsBlank,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "delete user from store",
			user:       models.ClientUser{Email: "newuser@gmail.com", Password: "hashed123"},
			store:      mockStore{[]models.ServerUser{NewUser1}},
			wantErr:    nil,
			wantStatus: http.StatusOK,
		},
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

func TestUpdate(t *testing.T) {
	updateTests := []struct {
		name             string
		currentUserEmail string
		updatedUser      models.ClientUser
		store            mockStore
		wantStatus       int
	}{
		{
			name:             "HAPPY path: update email only",
			currentUserEmail: "newuser@gmail.com",
			updatedUser:      models.ClientUser{Email: "user@gmail.com"},
			store:            mockStore{[]models.ServerUser{NewUser1}},
			wantStatus:       http.StatusOK,
		},
		{
			name:             "HAPPY path: update both email and password",
			currentUserEmail: "newuser@gmail.com",
			updatedUser:      models.ClientUser{Email: "user@gmail.com", Password: "plaintext"},
			store:            mockStore{[]models.ServerUser{NewUser1}},
			wantStatus:       http.StatusOK,
		},
		{
			name:             "sad path: blank email",
			currentUserEmail: "newuser@gmail.com",
			updatedUser:      models.ClientUser{},
			store:            mockStore{[]models.ServerUser{NewUser1}},
			wantStatus:       http.StatusBadRequest,
		},
		{
			name:             "sad path: same email",
			currentUserEmail: "newuser@gmail.com",
			updatedUser:      models.ClientUser{Email: "newuser@gmail.com"},
			store:            mockStore{[]models.ServerUser{NewUser1}},
			wantStatus:       http.StatusBadRequest,
		},
	}
	for _, test := range updateTests {
		fmt.Println("running test:", test.name)

		jwtToken, err := jsonWebTokes.GenAuthToken(test.currentUserEmail)
		if err != nil {
			t.Fatal(err)
		}

		c := &http.Cookie{
			Name:     "jwt",
			Value:    jwtToken,
			HttpOnly: true,
			Expires:  time.Now().Add(5 * time.Minute),
			Path:     "/",
		}

		clientData := url.Values{
			"Email":    {test.updatedUser.Email},
			"Password": {test.updatedUser.Password},
		}
		body := strings.NewReader(clientData.Encode())
		req, _ := http.NewRequest(http.MethodPost, "/update-user", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(c)

		resRec := httptest.NewRecorder()

		ms := test.store
		s := NewLoginServer(&ms)

		s.ServeHTTP(resRec, req)

		gotStatus := resRec.Code
		wantStatus := test.wantStatus

		if gotStatus != wantStatus {
			t.Errorf("got status code %d, want status code %d", gotStatus, wantStatus)
			byte, _ := io.ReadAll(resRec.Result().Body)
			fmt.Printf("%s \n", byte)
		}
	}
}

func TestLogin(t *testing.T) {
	updateTests := []struct {
		name       string
		user       models.ClientUser
		store      mockStore
		wantStatus int
	}{
		{
			name:       "sad path: empty email",
			user:       models.ClientUser{Password: "hashed123"},
			store:      mockStore{[]models.ServerUser{NewUser1}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "sad path: empty password",
			user:       models.ClientUser{Email: "newuser@gmail.com"},
			store:      mockStore{[]models.ServerUser{NewUser1}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "HAPPY path: login user password",
			user:       models.ClientUser{Email: "newuser@gmail.com", Password: "hashed123"},
			store:      mockStore{[]models.ServerUser{NewUser1}},
			wantStatus: http.StatusOK,
		},
		{
			name:       "sad path: login user bad password",
			user:       models.ClientUser{Email: "newuser@gmail.com", Password: "hashed321"},
			store:      mockStore{[]models.ServerUser{NewUser1}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "sad path: login user does not exist",
			user:       models.ClientUser{Email: "olduser@gmail.com", Password: "hashed321"},
			store:      mockStore{[]models.ServerUser{NewUser1}},
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, test := range updateTests {
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
			// byte, _ := io.ReadAll(resRec.Result().Body)
			// fmt.Printf("%s \n", byte)
		} else if gotStatus == 200 && wantStatus == 200 {
			response := resRec.Result()
			for _, cookie := range response.Cookies() {
				issuer, err := jsonWebTokes.CheckAuthToken(cookie.Value)
				if err == nil {
					if issuer != test.user.Email {
						t.Errorf("got cookie issuer %q, want %q", issuer, test.user.Email)
					}
				}
			}
		}

	}
}
