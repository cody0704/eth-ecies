# ETH-ECIES

## Example

```bash
package main

import (
    "fmt"
    "log"
    
	ethecies "github.com/cody0704/eth-ecies"
)

func main() {
    key := ethecies.LoadKey("A83DC2DC5D53E83CE0C6B8E2751317A905EC0491E83A0CAF0C58B753F7808810")

	ciphertext, signature, err := key.Encrypt("HI Cody")
    if err != nil{
        log.Println(err)
    }
    fmt.Println("ciphertext:", ciphertext)
    fmt.Println("signature:", signature)

	plaintext, err := key.Decrypt(ciphertext, signature)
    if err != nil{
        log.Println(err)
    }
    fmt.Println("plaintext:", plaintext)
}
```