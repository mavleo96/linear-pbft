package database

import (
	"errors"
	"strconv"

	"github.com/mavleo96/pbft/pb"
	"go.etcd.io/bbolt"
)

// Database represents a wrapper around a bbolt database.
type Database struct {
	db *bbolt.DB
}

// InitDB initializes the database with "balances" bucket and adds accounts
// for the given account IDs, setting their initial balance.
func (d *Database) InitDB(dbPath string, accountIds []string, initBalance int64) (err error) {
	boltDB, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return err
	}
	d.db = boltDB

	return d.db.Update(func(tx *bbolt.Tx) error {
		// Create the "balances" bucket
		_, err := tx.CreateBucket([]byte("balances"))
		if err != nil {
			d.db.Close()
			return err
		}

		// Add each account with an initial balance
		b := tx.Bucket([]byte("balances"))
		for _, id := range accountIds {
			if err := b.Put([]byte(id), []byte(strconv.FormatInt(initBalance, 10))); err != nil {
				return err
			}
		}
		return nil
	})
}

// ResetDB resets the database by setting the initial balance for all accounts to the given value.
func (d *Database) ResetDB(initBalance int64) (err error) {
	return d.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("balances"))
		if b == nil {
			return errors.New("balances bucket not found")
		}
		return b.ForEach(func(k, _ []byte) error {
			return b.Put([]byte(string(k)), []byte(strconv.FormatInt(initBalance, 10)))
		})
	})
}

// TODO: need to think about handling errors from the database.
// UpdateDB processes a transaction by updating the balances of the sender and receiver.
// It returns true if the transaction was successful, or false if the sender had insufficient funds.
func (d *Database) UpdateDB(t *pb.Transaction) (bool, error) {
	var success bool

	err := d.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("balances"))
		if b == nil {
			return errors.New("balances bucket not found")
		}

		// Retrieve sender and receiver balances
		senderBalBytes := b.Get([]byte(t.Sender))
		if senderBalBytes == nil {
			success = false
			return nil
		}
		receiverBalBytes := b.Get([]byte(t.Receiver))
		if receiverBalBytes == nil {
			success = false
			return nil
		}
		senderBal, err := strconv.Atoi(string(senderBalBytes))
		if err != nil {
			return err
		}
		receiverBal, err := strconv.Atoi(string(receiverBalBytes))
		if err != nil {
			return err
		}

		// Check if amount is valid and sender has sufficient balance
		amount := int(t.Amount)
		if amount <= 0 || senderBal < amount {
			success = false
			return nil
		}

		// Update balances
		if err := b.Put([]byte(t.Sender), []byte(strconv.Itoa(senderBal-amount))); err != nil {
			return err
		}
		if err := b.Put([]byte(t.Receiver), []byte(strconv.Itoa(receiverBal+amount))); err != nil {
			return err
		}
		success = true
		return nil
	})
	return success, err
}

// GetBalance retrieves the balance of the given account.
func (d *Database) GetBalance(account string) (int64, error) {
	var balance int64
	err := d.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("balances"))
		if b == nil {
			return errors.New("balances bucket not found")
		}
		balanceBytes := b.Get([]byte(account))
		if balanceBytes == nil {
			return errors.New("account not found")
		}
		val, err := strconv.ParseInt(string(balanceBytes), 10, 64)
		if err != nil {
			return err
		}
		balance = val
		return nil
	})
	return balance, err
}

// SetBalance sets the balance of the given account.
func (d *Database) SetBalance(account string, balance int64) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("balances"))
		if b == nil {
			return errors.New("balances bucket not found")
		}
		return b.Put([]byte(account), []byte(strconv.FormatInt(balance, 10)))
	})
}

// GetDBState gets the current state of the database.
func (d *Database) GetDBState() (map[string]int64, error) {
	dbState := make(map[string]int64)

	err := d.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("balances"))
		if b == nil {
			return errors.New("balances bucket not found")
		}
		return b.ForEach(func(k, v []byte) error {
			val, err := strconv.ParseInt(string(v), 10, 64)
			if err != nil {
				return err
			}
			dbState[string(k)] = val
			return nil
		})
	})
	return dbState, err
}

// Close closes the database
func (d *Database) Close() error {
	if d.db == nil {
		return nil
	}
	return d.db.Close()
}
