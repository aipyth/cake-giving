coverage-info:
	go test -v -race -coverprofile cover.out .
	go tool cover -html=cover.out -o cover.html
	firefox cover.html

