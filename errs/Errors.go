package errs

type Errs string

func (e Errs) Error() string {
	return string(e)
}

const (
	UserAlreadyExists      = Errs("Cannot register user as there is already an existing user with the same email")
	UserNotFound           = Errs("Specified user not found")
	EmailIsBlank           = Errs("Cannot enter blank username")
	PasswordIsBlank        = Errs("Cannot enter blank password")
	LoginFailed            = Errs("Login failed")
	LoginFailedBadPassword = Errs("Login failed")
	EnvVarNotFound         = Errs("environment variable could not be found. check .env file?")
)
