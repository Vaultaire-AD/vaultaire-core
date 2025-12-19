package storage

type Trames_struct_client struct {
	Message_Order       []string
	Destination_Server  string
	SessionIntegritykey string
	Username            string
	Domain              string
	ClientSoftwareID    string
	Content             string
}

type Trames_struct struct {
	Message_Order      []string
	Destination_Server string
	Content            string
}
