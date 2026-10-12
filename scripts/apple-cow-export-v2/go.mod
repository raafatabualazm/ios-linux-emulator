module codex/apple-cow-export-v2

go 1.26.5

require github.com/deploymenttheory/go-apfs-v2 v0.9.0

require (
	github.com/go-compressions/lzfse v0.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/ulikunitz/xz v0.5.16 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	howett.net/plist v1.0.1 // indirect
)


require codex/cowreader v0.0.0

replace codex/cowreader => ../apple-cow-reader
