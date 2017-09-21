# go-https-everywhere
HTTPS Everywhere rewrite engine implementation in Golang.

Contains exports for both _server_ and client-side use, as in, the construction of the rulesets in compressed format
and the reconstruction into memory, and finally the actual intended URL rewrite logic.

Matching and rewrite operations use a regex interface bridge (defined in the [utils](https://github.com/tenta-browser/goutils) package), which can be implemented in the target environment.

Currently the cookie securing feature is not present, but will be in a future iteration.

Exported functions:
* Parse() - reads, and constructs the rulesets into memory
* Encode()/Decode()/EncodeToPath() - handles encode and decode operations
* TryRewrite() - searches and (if applicable) rewrites the input url according to the rewrite rules

For a more detailed description of the operating principles, please consult the header paragraph of `https.go`
