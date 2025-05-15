# 编译
windows----------------------------------------------------------------
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -trimpath -o dddd64.exe main.go
upx.exe -9 dddd64.exe


linux------------------------------------------------------------------
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -trimpath -o dddd_linux64 main.go
upx.exe -9 dddd_linux64
