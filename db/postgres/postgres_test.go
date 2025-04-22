package pg

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/ganglinwu/secure-login-v3/models"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type PostgresTestSuite struct {
	suite.Suite
	container *postgres.PostgresContainer
	pgs       *PostgresStore
}

/*
*
* BEGIN TEST SUITE
*
*
 */

func TestPostgresTestSuite(t *testing.T) {
	suite.Run(t, &PostgresTestSuite{})
}

func (pts *PostgresTestSuite) SetupSuite() {
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:17.0",
		postgres.WithDatabase("usersDB"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("password123"),
		/*
			*
			*
			* not available until the next release of testcontainers-go
			*
			*
			    testcontainers.WithMounts([]testcontainers.ContainerMounts{
			    {
			      {
			          Source: testcontainers.GenericVolumeMountSource{Name: "appdata"},
			          Target: "./pgdata",
			        },
			      },
			    }),
		*/
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(5*time.Second)),
	)
	if err != nil {
		pts.T().Fatal("failed to load container", err)
	}

	connURI, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pts.T().Fatal("failed to get connection string", err)
	}
	pts.container = container

	db, err := sql.Open("pgx", connURI)
	if err != nil {
		pts.T().Fatal("failed to open db", err)
	}
	pts.pgs = NewPostgresStore(db)

	_, err = pts.pgs.db.ExecContext(ctx, "create table users (email varchar(255) primary key, password char(60) not null, created_at timestamptz default current_timestamp, updated_at timestamptz default current_timestamp);")
	if err != nil {
		pts.T().Fatal("failed to create table")
	}
	_, err = pts.pgs.db.ExecContext(ctx, "create or replace function fn_update_timestamp() returns trigger as $$ begin if row(NEW.*) is distinct from row(OLD.*) then NEW.updated_at = now(); return new; else return old; end if; end; $$ language plpgsql;")
	if err != nil {
		pts.T().Fatal("failed to create pgsql function to auto-update timestamp")
	}
	_, err = pts.pgs.db.ExecContext(ctx, "create trigger tgr_update_updated_at BEFORE update on users for each row execute procedure fn_update_timestamp();")
	if err != nil {
		pts.T().Fatal("failed to create pgsql trigger")
	}

	_, err = pts.pgs.db.ExecContext(ctx, "insert into users(email, password) values ('user1@user.com', '$2a$10$iTEKSQ9oeJ30X0dJ90fBe.TTqWPewLXBqzWFLq77TmrVHpLstRJJC'), ('user2@user.com','$2a$10$5xtU24NiH8pQJFVeLSYEAOjuLdz1lMSk3wEbty.JonWGYiWOozjV.');")
	if err != nil {
		pts.T().Fatal("failed to seed data into db")
	}
}

func (pts *PostgresTestSuite) TearDownSuite() {
	testcontainers.CleanupContainer(pts.T(), pts.container)
}

/*
*
* END TEST SUITE
*
*
 */

func (pts *PostgresTestSuite) TestRegisterUser() {
	registerTests := []struct {
		name string
		user models.ServerUser
		want error
	}{
		/*
		 *
		 * we don't test for blank password or blank email because that is caught by controllers
		 *
		 */
		{"happy path: register user1", models.ServerUser{Email: "test@test.com", HPassword: ""}, nil},
		{"sad path: register user that already exists", models.ServerUser{Email: "test@test.com", HPassword: ""}, error(fmt.Errorf("user with email already exists"))},
	}

	for _, test := range registerTests {
		fmt.Println("running test:", test.name)
		got := pts.pgs.RegisterNewUser(test.user)
		want := test.want

		if got != want {
			if got == nil {
				pts.T().Errorf("got nil error, want %q", want.Error())
			} else if want == nil {
				pts.T().Errorf("got %q, want nil error", got.Error())
			}
		}
	}
}

func (pts *PostgresTestSuite) TestFetchUser() {
	lookupTests := []struct {
		name      string
		userEmail string
		want      models.ClientUser
		wantErr   error
	}{
		{"happy path: fetch user1@user.com", "user1@user.com", models.ClientUser{Email: "user1@user.com", Password: "user1"}, nil},
		{"sad path: fetch non-existant user user999@user.com", "user999@user.com", models.ClientUser{}, error(fmt.Errorf("sql: no rows in result set"))},
	}

	for _, test := range lookupTests {
		fmt.Println("running test:", test.name)
		got, goterr := pts.pgs.FetchUser(test.userEmail)

		if got.Email != test.want.Email {
			pts.T().Errorf("got %q, want %q \n", got.Email, test.want.Email)
		}

		if goterr == nil && test.wantErr != nil {
			pts.T().Errorf("got nil error \n, want error %s\n", test.wantErr.Error())
		} else if test.wantErr == nil && goterr != nil {
			pts.T().Errorf("got error %s\n, want nil error n", goterr.Error())
		} else if goterr != nil && test.wantErr != nil {
			if goterr.Error() != test.wantErr.Error() {
				pts.T().Errorf("got %s\n, want error %s\n", goterr.Error(), test.wantErr.Error())
			}
		} // if both errors are nil, that is a successful test result

	}
}

func (pts *PostgresTestSuite) TestRemoveUser() {
	RemoveTests := []struct {
		name    string
		user    models.ServerUser
		wantErr error
	}{
		{"happy path: delete user1@user.com", models.ServerUser{Email: "user1@user.com", HPassword: "$2a$10$iTEKSQ9oeJ30X0dJ90fBe.TTqWPewLXBqzWFLq77TmrVHpLstRJJC"}, nil},
		{"sad path: delete non-existant user user999@user.com", models.ServerUser{Email: "user999@user.com", HPassword: "$2a$10$b5HDZ19uPf3n9nSA4obULeyjF5QxvWHocg3C0C6vz3BIE8YMyWEu."}, error(fmt.Errorf("no rows deleted"))},
	}

	for _, test := range RemoveTests {
		fmt.Println("running test:", test.name)
		goterr := pts.pgs.RemoveUser(test.user)

		if goterr == nil && test.wantErr != nil {
			pts.T().Errorf("got nil error \n, want error %s\n", test.wantErr.Error())
		} else if test.wantErr == nil && goterr != nil {
			pts.T().Errorf("got error %s\n, want nil error n", goterr.Error())
		} else if goterr != nil && test.wantErr != nil {
			if goterr.Error() != test.wantErr.Error() {
				pts.T().Errorf("got %s\n, want error %s\n", goterr.Error(), test.wantErr.Error())
			}
		} // if both errors are nil, that is a successful test result

	}
}

func (pts *PostgresTestSuite) TestUpdateUser() {
	updateTests := []struct {
		name        string
		currentUser string
		newUser     string
		wantErr     error
	}{
		{"happy path: update user2@user.com", "user2@user.com", "newuser@user.com", nil},
		{"sad path: update non-existant user user999@user.com", "user999@user.com", "newuser@user.com", error(fmt.Errorf("no rows updated"))},
	}

	for _, test := range updateTests {
		fmt.Println("running test:", test.name)
		goterr := pts.pgs.UpdateUser(test.currentUser, test.newUser)

		if goterr == nil && test.wantErr != nil {
			pts.T().Errorf("got nil error \n, want error %s\n", test.wantErr.Error())
		} else if test.wantErr == nil && goterr != nil {
			pts.T().Errorf("got error %s\n, want nil error n", goterr.Error())
		} else if goterr != nil && test.wantErr != nil {
			if goterr.Error() != test.wantErr.Error() {
				pts.T().Errorf("got %s\n, want error %s\n", goterr.Error(), test.wantErr.Error())
			}
		} // if both errors are nil, that is a successful test result

	}
}

func (pts *PostgresTestSuite) TestLogin() {
	loginTests := []struct {
		name    string
		user    models.ClientUser
		wantErr error
	}{
		{"happy path: login user1@user.com", models.ClientUser{Email: "user1@user.com", Password: "user1"}, nil},
		{"sad path: login non-existant user user999@user.com", models.ClientUser{Email: "user999@user.com", Password: "user999"}, error(fmt.Errorf("user does not exists"))},
	}

	for _, test := range loginTests {
		fmt.Println("running test:", test.name)
		goterr := pts.pgs.Login(test.user)

		if goterr == nil && test.wantErr != nil {
			pts.T().Errorf("got nil error \n, want error %s\n", test.wantErr.Error())
		} else if test.wantErr == nil && goterr != nil {
			pts.T().Errorf("got error %s\n, want nil error n", goterr.Error())
		} else if goterr != nil && test.wantErr != nil {
			if goterr.Error() != test.wantErr.Error() {
				pts.T().Errorf("got %s\n, want error %s\n", goterr.Error(), test.wantErr.Error())
			}
		}
	}
}
