package database

import (
	"errors"

	"go.etcd.io/bbolt"
)

// Generic key-value operations for YCSB benchmarking

// PutKeyValue stores a key-value pair in the specified table/bucket
func (d *Database) PutKeyValue(table string, key string, value []byte) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(table))
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), value)
	})
}

// GetKeyValue retrieves a value for a key from the specified table/bucket
func (d *Database) GetKeyValue(table string, key string) ([]byte, error) {
	var value []byte
	err := d.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return errors.New("table not found: " + table)
		}
		v := bucket.Get([]byte(key))
		if v == nil {
			return errors.New("key not found: " + key)
		}
		value = make([]byte, len(v))
		copy(value, v)
		return nil
	})
	return value, err
}

// UpdateKeyValue updates a key-value pair in the specified table/bucket
func (d *Database) UpdateKeyValue(table string, key string, value []byte) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return errors.New("table not found: " + table)
		}
		// Check if key exists
		existing := bucket.Get([]byte(key))
		if existing == nil {
			return errors.New("key not found: " + key)
		}
		return bucket.Put([]byte(key), value)
	})
}

// DeleteKeyValue deletes a key from the specified table/bucket
func (d *Database) DeleteKeyValue(table string, key string) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return nil // Table doesn't exist, nothing to delete
		}
		return bucket.Delete([]byte(key))
	})
}

// ScanKeyValue scans records from the specified table/bucket
func (d *Database) ScanKeyValue(table string, startKey string, count int) ([]struct {
	Key   string
	Value []byte
}, error) {
	var results []struct {
		Key   string
		Value []byte
	}
	err := d.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return errors.New("table not found: " + table)
		}
		cursor := bucket.Cursor()
		key, value := cursor.Seek([]byte(startKey))
		for i := 0; key != nil && i < count; i++ {
			results = append(results, struct {
				Key   string
				Value []byte
			}{
				Key:   string(key),
				Value: append([]byte(nil), value...),
			})
			key, value = cursor.Next()
		}
		return nil
	})
	return results, err
}
