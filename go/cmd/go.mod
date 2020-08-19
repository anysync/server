module github.com/anysync/server/cmd

go 1.12

require (
	github.com/VividCortex/ewma v1.1.1 // indirect
	github.com/anysync/server/client v0.0.0-00010101000000-000000000000 // indirect
	github.com/anysync/server/server v0.0.0
	github.com/anysync/server/utils v0.0.0
	github.com/h2non/filetype v1.1.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.1 // indirect
	github.com/panjf2000/ants v1.3.0 // indirect
	github.com/rclone/rclone v1.52.3 // indirect
	github.com/soheilhy/cmux v0.1.4
	google.golang.org/grpc v1.27.1
)

replace github.com/anysync/server/utils => ../pkg/utils

replace github.com/anysync/server/server => ../pkg/server

replace github.com/anysync/server/client => ../pkg/client
