module main

go 1.24rc1

require (
	github.com/gorilla/mux v1.8.1
	github.com/salrashid123/go_ech/util v0.0.0
	golang.org/x/net v0.34.0
)

require (
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)

replace github.com/salrashid123/go_ech/util => ../util
