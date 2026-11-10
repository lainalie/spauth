@mkdir bin
del /f /q .\bin\*.*

go mod tidy
set CGO_ENABLED=0&& set GOOS=windows&& set GOARCH=amd64&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-windows-amd64.exe ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=windows&& set GOARCH=arm64&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-windows-arm64.exe ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=windows&& set GOARCH=386&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-windows-386.exe ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=linux&& set GOARCH=amd64&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-linux-amd64 ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=linux&& set GOARCH=386&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-linux-386 ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=linux&& set GOARCH=arm64&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-linux-arm64 ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=linux&& set GOARCH=arm&& set GOARM=7&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-linux-armv7 ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=linux&& set GOARCH=arm&& set GOARM=6&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-linux-armv6 ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=darwin&& set GOARCH=amd64&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-darwin-amd64 ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=darwin&& set GOARCH=arm64&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-darwin-arm64 ./cmd/spa-cli
set CGO_ENABLED=0&& set GOOS=freebsd&& set GOARCH=amd64&& go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin\spa-cli-freebsd-amd64 ./cmd/spa-cli

pause