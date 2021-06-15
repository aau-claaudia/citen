# citen
citen is a special one-purpose ssh daemon. It allows for authenticated jumps to preconfigured networks by probing destinations for public key acceptance.

Using citen, you can create a jump host that knows nothing about its users or their keypairs; every time a user tries to make a so-called direct-tcpip tunnel, citen will ask the destination if it should allow it. 

citen uses a lesser-known feature of the ssh protocol; you don't have to possess a keypairs private key to ask an ssh daemon if authentication can proceed.

This diagram describes the sequence in more detail: [citen-success-sequence.png](./docs/citen-success-sequence.png)

## Relevant RFCs
[SSH Authentication Protocol - 7.  Public Key Authentication Method: "publickey"](https://datatracker.ietf.org/doc/html/rfc4252#section-7)

[The Secure Shell (SSH) Connection Protocol - 7.2. TCP/IP Forwarding Channels](https://datatracker.ietf.org/doc/html/rfc4254#section-7.2)



## Configuration
citen uses environment variables for configuration; there are two available:

`CITEN_LISTEN` - specifies where to listen for ssh connections. 
Default: `random unprivileged port on localhost`

`CITEN_ALLOW` - specifies network(s) to allow connections to in CIDR notation.
Maybe comma seperated
Default: `0.0.0.0/0`

Take care when defining `CITEN_ALLOW`. If left default, it will proxy to any destination.

## Running citen
As root, and with openssh moved out of the way, run:
```
$ CITEN_ALLOW="192.168.1.0/24" CITEN_LISTEN="0.0.0.0:22" citen 
2020/08/06 16:49:51 Listening on [::]:22
```

Note: citen needs a host key in order to accept SSH traffic - you may have to generate a new SSH key pair by running `ssh-keygen`, citen expects a private `id_rsa` key in its work directory.

## Using citen
Now that citen is running; you can use the ssh client's `-J` parameter to jump through it to another host located in the allowed network, e.g.:

```
ssh -J citen-hostname 192.168.1.100
```

citen is not limited to ssh connections. You could also access an HTTP server located in the network:

```
ssh -L8080:192.168.1.42:80 citen-hostname
```

`192.168.1.42:80` is now available on the client's localhost port 8080. 

The auth scheme still applies here, and `192.168.1.42`'s ssh daemon will have to accept the user and public key combo.
