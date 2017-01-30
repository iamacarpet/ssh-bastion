# SSH-BASTION
A logging SSH relay, with LDAP & public key auth.

## Logging Functionality
This application will MITM all SSH sessions directed at your internal servers and log the interactive sessions to disk.
Only interactive sessions are allowed, all other SSH channels (e.g. port forwarding, X11 forwarding) are denied (with the exception of ssh-agent for pass-through public key auth).

Each session will generate 3 log files,
 * a text file, containing the raw output of the session.
 * a .ttyrec file, which is a "ttyrecord" format recording, playable using "ttyplay".
 * a .req file containing all of the SSH requests sent by the client to the remote server during the session.

Authentication / session information is also logged to syslog with the LOG_AUTH | LOG_ALERT flags.

Only the output that is sent back to the client is logged, as the shell should echo any input from the client, with the exception of masked fields, like passwords.

The log directory is specified in the yaml config file and the files are stored in subdirectories of the year and month.

## How it works
When a user connects to the relay, they can authenticate with a user/pass which will be authed against LDAP (AD), or a public key allowed via an authorized_key file linked to the user in the yaml config.

After authenticating they will be presented with a list of servers that they can connect to, which after selecting it will connect them to and either pass through the password they already used, prompt them for another password, or use agent forwarding to pass through a public key.

The user is never offered a local shell and if one is required, it will have to go via a real sshd running locally.

A basic session should look like this:
```
Welcome to SSH Bastion Relay Agent.
This service is restricted to authorized users only.
All activities on this system are logged.

Please choose from the following servers:
    [  1 ] vdev1.ad.domain.local
    [  2 ] vdev2.ad.domain.local
Please Enter A Server ID: 2
Connecting to vdev2.ad.domain.local

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jan 1 00:00:59 1970 from localhost
user1@vdev2:~$ echo "test"
test
```

## Build & Usage
To build, you will need the Go runtime and to build you just need to run:

```
go build
```

To test run from the command line, you can run:

```
./ssh-bastion -c "path-to-yaml-config-file"
```

## Recommended Install Procedure
```
# useradd -d /opt/ssh-bastion -s /bin/false -c "SSH-BASTION SSH Relay" -r -U -m bastion
# mkdir -p /opt/ssh-bastion/data/{logs,keys,pub,users}
# cp <ssh-bastion binary location> /opt/ssh-bastion/ssh-bastion
# cp <motd example path> /opt/ssh-bastion/data/motd
# cp <config.yaml example path> /opt/ssh-bastion/config.yaml
# ssh-keygen -f /opt/ssh-bastion/data/keys/ssh_host_rsa_key -N '' -t rsa
# ssh-keygen -f /opt/ssh-bastion/data/keys/ssh_host_dsa_key -N '' -t dsa
# ssh-keygen -f /opt/ssh-bastion/data/keys/ssh_host_ecdsa_key -N '' -t ecdsa
# vi /opt/ssh-bastion/config.yaml (edit config as required)
# chown -R bastion:bastion /opt/ssh-bastion
# chmod 750 /opt/ssh-bastion
# cp <systemd/ssh-bastion.service location> /etc/systemd/system/ssh-bastion.service
# systemctl daemon-reload
# systemctl enable ssh-bastion
# systemctl start ssh-bastion
```

You will then need to customize the config to match your remote servers, copying their host public keys to the data/pub folder and linking them in the config.

Your data/logs folder will probably end up taking up quite a lot of space and eating up lots of disk I/O, so with that in mind it might be worth mounting it on another disk.

## Credits
Based on [sshmuxd](https://github.com/joushou/sshmuxd) with addition of logging and LDAP auth.
