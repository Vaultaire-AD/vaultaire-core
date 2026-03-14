package storage

type splitStorage struct {
	Split    int
	Content  string
	Username string
}

var tableSplitStorage []splitStorage
var TableSplitStorage *[]splitStorage = &tableSplitStorage
