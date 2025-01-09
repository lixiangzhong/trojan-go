package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	// MySQL Driver
	_ "github.com/go-sql-driver/mysql"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/statistic"
	"github.com/p4gefau1t/trojan-go/statistic/memory"
)

const Name = "MYSQL"

type Authenticator struct {
	*memory.Authenticator
	db             *sql.DB
	updateDuration time.Duration
	ctx            context.Context
}

func (a *Authenticator) updater() {
	tk := time.NewTicker(a.updateDuration)
	defer tk.Stop()
	for {
		var affected int64
		for _, user := range a.ListUsers() {
			// swap upload and download for users
			hash := user.Hash()
			sent, recv := user.ResetTraffic()
			if sent == 0 && recv == 0 {
				continue
			}
			s, err := a.db.Exec("UPDATE `users` SET `upload`=`upload`+?, `download`=`download`+? WHERE `password`=?;", recv, sent, hash)
			if err != nil {
				log.Error(common.NewError("failed to update data to user table").Base(err))
				continue
			}
			r, _ := s.RowsAffected()
			if r == 0 {
				a.DelUser(hash)
			}
			affected += r
		}
		log.Info("buffered data has been written into the database", "affected", affected)

		// update memory
		rows, err := a.db.Query("SELECT password,quota,download,upload,speed_sent,speed_recv FROM users")
		if err != nil || rows.Err() != nil {
			log.Error(common.NewError("failed to pull data from the database").Base(err))
			time.Sleep(a.updateDuration)
			continue
		}
		for rows.Next() {
			var hash string
			var quota, download, upload int64
			var speedSent, speedRecv int
			err := rows.Scan(&hash, &quota, &download, &upload, &speedSent, &speedRecv)
			if err != nil {
				log.Error(common.NewError("failed to obtain data from the query result").Base(err))
				break
			}
			if download+upload < quota || quota <= 0 {
				a.AddUser(hash)
				if exist, u := a.Authenticator.AuthUser(hash); exist {
					u.SetSpeedLimit(speedSent, speedRecv)
				}
			} else {
				a.DelUser(hash)
			}
		}
		rows.Close()
		log.Info("load data from database")

		select {
		case <-tk.C:
		case <-a.ctx.Done():
			log.Debug("MySQL daemon exiting...")
			return
		}
	}
}

func (a *Authenticator) AuthUser(hash string) (bool, statistic.User) {
	exist, u := a.Authenticator.AuthUser(hash)
	if exist {
		return exist, u
	}
	var quota, download, upload int64
	var speedSent, speedRecv int
	err := a.db.QueryRow("SELECT quota,download,upload,speed_sent,speed_recv FROM users WHERE password=?", hash).
		Scan(&quota, &download, &upload, &speedSent, &speedRecv)
	if err != nil {
		return false, nil
	}
	if download+upload < quota || quota <= 0 {
		a.AddUser(hash)
		if exist, u := a.Authenticator.AuthUser(hash); exist {
			u.SetSpeedLimit(speedSent, speedRecv)
		}
		return true, u
	}
	return false, nil
}

func connectDatabase(driverName, username, password, ip string, port int, dbName string) (*sql.DB, error) {
	path := strings.Join([]string{username, ":", password, "@tcp(", ip, ":", fmt.Sprintf("%d", port), ")/", dbName, "?charset=utf8"}, "")
	return sql.Open(driverName, path)
}

func NewAuthenticator(ctx context.Context) (statistic.Authenticator, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	db, err := connectDatabase(
		"mysql",
		cfg.MySQL.Username,
		cfg.MySQL.Password,
		cfg.MySQL.ServerHost,
		cfg.MySQL.ServerPort,
		cfg.MySQL.Database,
	)
	if err != nil {
		return nil, common.NewError("Failed to connect to database server").Base(err)
	}
	db.SetMaxOpenConns(10)
	a := &Authenticator{
		db:             db,
		ctx:            ctx,
		updateDuration: time.Duration(cfg.MySQL.CheckRate) * time.Second,
		Authenticator:  memory.NewAuthenticatorPlain(ctx),
	}
	go a.updater()
	log.Debug("mysql authenticator created")
	return a, nil
}

func init() {
	statistic.RegisterAuthenticatorCreator(Name, NewAuthenticator)
}
