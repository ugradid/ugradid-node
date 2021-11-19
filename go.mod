module github.com/ugradid/ugradid-node

go 1.17

require (
	github.com/deepmap/oapi-codegen v1.9.0
	github.com/google/uuid v1.1.2
	github.com/knadh/koanf v0.16.0
	github.com/labstack/echo/v4 v4.6.1
	github.com/lestrrat-go/jwx v1.2.10
	github.com/pkg/errors v0.9.1
	github.com/shengdoushi/base58 v1.0.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spaolacci/murmur3 v1.1.0
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/ugradid/ugradid-common v0.1.0
	github.com/ugradid/ugradid-eibb v0.1.0
	go.etcd.io/bbolt v1.3.6
	google.golang.org/grpc v1.42.0
	google.golang.org/protobuf v1.27.1
	schneider.vip/problem v1.6.0
)

replace github.com/ugradid/ugradid-common v0.1.0 => ../ugradid-common

replace github.com/ugradid/ugradid-eibb v0.1.0 => ../ugradid-eibb

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.0-20210816181553-5444fa50b93d // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/goccy/go-json v0.7.10 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/labstack/gommon v0.3.0 // indirect
	github.com/lestrrat-go/backoff/v2 v2.0.8 // indirect
	github.com/lestrrat-go/blackmagic v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.0 // indirect
	github.com/lestrrat-go/iter v1.0.1 // indirect
	github.com/lestrrat-go/option v1.0.0 // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mitchellh/copystructure v1.1.1 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/ockam-network/did v0.1.4-0.20210103172416-02ae01ce06d8 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/tidwall/gjson v1.11.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.1 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20210913180222-943fd674d43e // indirect
	golang.org/x/sys v0.0.0-20211031064116-611d5d643895 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba // indirect
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
