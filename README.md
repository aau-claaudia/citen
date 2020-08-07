# jump
------
jump is a no-authentication ssh daemon that only allows forward TCP channels. Use it to open up an otherwise NAT'd network when you want the entire internet to reach inside it.

## Configuration
jump uses environment variables for configuration; there are two available:

`JUMP_LISTEN` - specifies where to listen for ssh connections. 
Default: `random unprivileged port on localhost`

`JUMP_ALLOW` - specifies a network to allow connections to in CIDR notation.
Default: `0.0.0.0/0`

Take care when defining `JUMP_ALLOW`. If left default, you may end up unwillingly creating a global proxy server.


## Running jump
As root, and with openssh moved out of the way, run:
```
$ JUMP_ALLOW="192.168.1.0/24" JUMP_LISTEN="0.0.0.0:22" jump 
2020/08/06 16:49:51 Listening on [::]:22
```

Note: you may have to generate a new SSH keypair by running `ssh-keygen`, jump expects a private `id_rsa` key in its work directory.

jump will now allow any forward connection to the `192.168.1.0/24` network

## Using jump
Now, that jump is running, you can use the ssh client's -J parameter to jump though it to another host thats located in the allowed network, e.g.:

```
ssh -J jumphostname 192.168.1.100
```

This is not limited to ssh connections, you could also access a http server located in the network:

```
ssh -L8080:192.168.1.42:80 jumphostname
```

`192.168.1.42:80` is now available on the client's localhost port 8080

