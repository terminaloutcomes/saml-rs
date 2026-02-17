# saml-rs

My main aim at the moment is to provide IdP capabilities for the [Kanidm](https://github.com/kanidm/kanidm) project, if you want to help - please log PRs/Issues against [terminaloutcomes/saml-rs](https://github.com/terminaloutcomes/saml-rs).

## Please help

I can't work out how to get signed assertions to validate in any publicly-available SP implementation :(

This library's in a lot of flux right now, if you're using it from Github then... sorry? Once it's published as a crate you'll have a relatively stable target, as much as that'll help?

## Documentation

The automatically-generated documentation based on the `main` branch is here: <https://terminaloutcomes.github.io/saml-rs/saml_rs/>

## Generating the SAML keys for the test server

You'll need cloudflare's SSL toolkit [cloudflare/ssl](https://github.com/cloudflare/cfssl).

This assumes you're running it from `~/certs`

### Create a config.json

```json
{
    "hosts": [
        "example.com"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C":  "AU",
            "L":  "The Internet",
            "O":  "Example Org",
            "OU": "SAML",
            "ST": "Somewhere"
        }
    ]
}
```

### Running commands

This generates a CA cert, then signs a certificate for it with the same name. It's janky but it works.

```shell
$ cfssl genkey -initca config.json | cfssljson -bare ca
2021/07/30 23:58:29 [INFO] generate received request
2021/07/30 23:58:29 [INFO] received CSR
2021/07/30 23:58:29 [INFO] generating key: rsa-2048
2021/07/30 23:58:29 [INFO] encoded CSR
2021/07/30 23:58:29 [INFO] signed certificate with serial number 486163044885311370117893514213005435517027358051

$ cfssl gencert -ca ca.pem -ca-key ca-key.pem -hostname=example.com config.json | cfssljson -bare
2021/07/31 00:04:29 [INFO] generate received request
2021/07/31 00:04:29 [INFO] received CSR
2021/07/31 00:04:29 [INFO] generating key: rsa-2048
2021/07/31 00:04:29 [INFO] encoded CSR
2021/07/31 00:04:29 [INFO] signed certificate with serial number 31731242146728568970438012635101523767577144558

```

You end up with files you can specify in the config here:

```json
"saml_cert_path" : "~/certs/cert.pem",
"saml_key_path" : "~/certs/cert-key.pem"
```
