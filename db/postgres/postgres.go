package pg

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ganglinwu/secure-login-v3/models"
)

type PostgresStore struct {
	db *sql.DB
}

/*
RegisterNewUser(models.ServerUser) error
FetchUser(string) (*models.ServerUser, error)
RemoveUser(models.ServerUser) error
UpdateUser(string string) error
Login(models.ClientUser) error
*/
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (pgs *PostgresStore) RegisterNewUser(user models.ServerUser) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := pgs.db.Conn(ctx)
	if err != nil {
		return err
	}

	fetchedUser := models.ServerUser{}

	err = conn.QueryRowContext(ctx, "select * from users where email =$1", user.Email).Scan(&fetchedUser.Email, &fetchedUser.HPassword, &fetchedUser.Created_at, &fetchedUser.Updated_at)

	switch err {
	case sql.ErrNoRows:
	case nil:
		return error(fmt.Errorf("user with email already exists"))
	default:
		return err
	}

	_, err = conn.ExecContext(ctx, "insert into users (email, password) values ($1, $2)", user.Email, user.HPassword)
	if err != nil {
		return err
	}
	return nil
}

func (pgs *PostgresStore) FetchUser(email string) (*models.ServerUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := pgs.db.Conn(ctx)
	if err != nil {
		return &models.ServerUser{}, err
	}

	fetchedUser := models.ServerUser{}

	err = conn.QueryRowContext(ctx, "select * from users where email=$1", email).Scan(&fetchedUser.Email, &fetchedUser.HPassword, &fetchedUser.Created_at, &fetchedUser.Updated_at)
	if err != nil {
		return &models.ServerUser{}, err
	}
	return &fetchedUser, nil
}

func (pgs *PostgresStore) RemoveUser(user models.ServerUser) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := pgs.db.Conn(ctx)
	if err != nil {
		return err
	}

	tx, err := conn.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelDefault,
		ReadOnly:  false,
	})
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "delete from users where email=$1", user.Email)
	if err == nil {
		count, err := result.RowsAffected()
		if err == nil {
			if count == 0 {
				tx.Rollback()
				return error(fmt.Errorf("no rows deleted"))
			} else if count == 1 {
				err := tx.Commit()
				if err != nil {
					return err
				}
				return nil
			} else {
				tx.Rollback()
				return error(fmt.Errorf("multiple rows were marked for delete. rolling back transaction"))
			}
		}
	}
	return nil
}

func (pgs *PostgresStore) UpdateUser(currentEmail, newEmail string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := pgs.db.Conn(ctx)
	if err != nil {
		return err
	}

	tx, err := conn.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelDefault,
		ReadOnly:  false,
	})
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "update users set email=$2 where email=$1", currentEmail, newEmail)
	if err == nil {
		count, err := result.RowsAffected()
		if err == nil {
			if count == 0 {
				tx.Rollback()
				return error(fmt.Errorf("no rows updated"))
			} else if count == 1 {
				err := tx.Commit()
				if err != nil {
					return err
				}
				return nil
			} else {
				tx.Rollback()
				return error(fmt.Errorf("multiple rows were marked for update. rolling back transaction"))
			}
		}
	}
	return nil
}

func (pgs *PostgresStore) Login(user models.ClientUser) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := pgs.db.Conn(ctx)
	if err != nil {
		return err
	}

	fetchedUser := models.ServerUser{}

	err = conn.QueryRowContext(ctx, "select * from users where email =$1", user.Email).Scan(&fetchedUser.Email, &fetchedUser.HPassword, &fetchedUser.Created_at, &fetchedUser.Updated_at)

	switch err {
	case sql.ErrNoRows:
		return error(fmt.Errorf("user does not exists"))
	case nil:
		return nil
	default:
		return err
	}
}
