package main

import (
    "fmt"
    "log"
    "golang.org/x/crypto/ssh"
    ldap "github.com/tonnerre/go-ldap"
)

func AuthUserPass(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
    perm := &ssh.Permissions{
        Extensions: map[string]string{
            "authType":     "password",
            "password":     string(password),
        },
    }

    if _, ok := config.Users[conn.User()]; ! ok {
        return nil, fmt.Errorf("User Doesn't Exist in Config")
    }

    if config.Global.AuthType == "ad" {
        l, err := ldap.Dial("tcp", config.Global.LDAP_Server)
        if err != nil {
            log.Printf("LDAP Connect Failed: %s", err)
            return nil, fmt.Errorf("LDAP Connect Failed: %s", err)
        }

        if err := l.Bind(fmt.Sprintf("%s@%s", conn.User(), config.Global.LDAP_Domain), string(password)); err != nil {
            log.Printf("LDAP Bind Failed: %s", err)
            return nil, fmt.Errorf("LDAP Bind Failed: %s", err)
        }

        return perm, nil
    } else {
        return nil, fmt.Errorf("No Valid Auth Types")
    }
}
