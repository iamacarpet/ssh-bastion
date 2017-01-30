package main

import (
    "fmt"
    "io/ioutil"
    "gopkg.in/yaml.v2"
)

type SSHConfig struct {
    Global                  SSHConfigGlobal                 `yaml:"global"`
    Servers                 map[string]SSHConfigServer      `yaml:"servers"`
    ACLs                    map[string]SSHConfigACL         `yaml:"acls"`
    Users                   map[string]SSHConfigUser        `yaml:"users"`
}

type SSHConfigGlobal struct {
    MOTDPath                string                          `yaml:"motd_path"`
    LogPath                 string                          `yaml:"log_path"`
    HostKeyPaths            []string                        `yaml:"host_keys"`
    AuthType                string                          `yaml:"auth_type"`
    LDAP_Server             string                          `yaml:"ldap_server"`
    LDAP_Domain             string                          `yaml:"ldap_domain"`
    PassPassword            bool                            `yaml:"pass_password"`
    ListenPath              string                          `yaml:"listen_path"`
}

type SSHConfigServer struct {
    HostPubKeyFiles         []string                        `yaml:"host_pubkeys"`
    ConnectPath             string                          `yaml:"connect_path"`
}

type SSHConfigACL struct {
    AllowedServers          []string                        `yaml:"allow_list"`
}

type SSHConfigUser struct {
    ACL                     string                          `yaml:"acl"`
    AuthorizedKeysFile      string                          `yaml:"authorized_keys_file"`
}

func fetchConfig(filename string) (*SSHConfig, error) {
    configData, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("Failed to open config file: %s", err)
    }

    config := &SSHConfig{}

    err = yaml.Unmarshal(configData, config)
    if err != nil {
        return nil, fmt.Errorf("Unable to parse YAML config file: %s", err)
    }

    return config, nil
}
