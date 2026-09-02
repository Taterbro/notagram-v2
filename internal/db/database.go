package db

import (
	"database/sql"

	_ "github.com/lib/pq"
)

func Connect(url string) error {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		return err
	}
	return nil

}
