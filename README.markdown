# e #

## What is it? ##

This toy project is an attempt to provide some kind of automation to hide sensitive data in text files, e.g. dotfiles.

It consists of:

- `e` - primitives library
- `e-aesgcm` - custom implementation of asymmetric encryption using AES-GCM on RSA keys
- `e-gpgme` - implementation of encryption over `gpgme` library
- `e-exe` - executable to encrypt/decrypt text files. Depends on `e`, `e-aesgcm` and `e-gpgme`

## What is it needed for? ##

### Goal ###

_Hide sensitive data inside text files in a readable and compact manner._

At the first glance, it's a pretty straight forward task, like, err, encrypt the file, and ... that's it.
However, it doesn't make much sense since:

- Is it really necessary to encrypt entire file just to hide a single password inside?
- How to reason about the rest of the file, since it's but an encrypted jibberish?
- How to have a readable diff when only plain text was changed?
- How to have a readable diff when only one of the sensitive values was changed?
- How to update all the usages of a given sensitive value in many files?
- etc.

All this can be summarized in some kind of requirements.

### Requirements ###

- Support various encryption/key-storing mechanisms (per encrypted value).

- Adding new portion of secrets to already encrypted text file should not modify previously encrypted values.

- Only sensitive data is hidden, the rest should be left intact.

- Ciphered values should not be part of the file (in order to make it readable and compact).

- Single ciphered value could be referenced many times.

- [TODO] Single ciphered value could be referenced in many files.

## Template syntax ##

`Tem` could contain plain text, plain values `PlainValue` that would be encrypted, and references to already encrypted values `ValRef`.

### 'PlainValue' syntax ###

`{{P|<variable name>|<encryption algorithm name>|<arguments>|<content>}}`

E.g. `{{P|username|gpgme|keyId = foobar|bazqux}}` stands for sensitive content "bazqux" that need to be encrypted with "gpgme" algorithm with "foobar" keyId, and stored as "username".

### 'ValRef' syntax ###

`{{E|<variable name>}}`

E.g. `{{E|username}}`.

- `<variable name>`. Name of the variable stored in `Metadata` which could be referenced in `ValRef`.
- `<encryption algorithm name>`. `AlgName` provided by one of the algorithms `Algs` used for encryption/decryption.
- `<arguments>`. Arguments that encryption algorithm `Algs` use during encryption/decryption.
- `<content>`. Sensitive data to encrypt.

## How to install? ##

Run either `cabal new-build` or `stack build` in `e-exe` directory.

## How to use? ##

Let's try to hide sensitive data in `"password = qwerty123!"` string using `gpgme` `Alg` from `e-gpgme` package.

_Note: there is 8FCB631E gpg key used which is probably absent on your machine and should be substituted with another one._

### Using `e` library

```
$> cd e && cabal new-repl

ghci> :m + E E.Algorithm.Gpgme
ghci> :set -XTypeApplications

ghci> plain = pack "password = {{P|password|gpgme|keyId = 8FCB631E|qwerty123!}}"

ghci> Just tem = decode @Tem plain

ghci> tem
"password = " `Txt` (PlainValue (ValName {unValueName = "password"}) (AlgName {unAlgName = "gpgme"}) (Args {unArgs = fromList [(ArgName {unArgName = "keyId"},ArgValue {unArgValue = "8FCB631E"})]}) (PlainContent {unPlainContent = "qwerty123!"}) `Val` Nil)

ghci> Right (tem', meta) <- runEitherT $ encryptTem gpgme mempty tem

ghci> meta
Metadata {unMetadata = fromList [(ValName {unValueName = "password"},EncValue (AlgName {unAlgName = "gpgme"}) (Args {unArgs = fromList [(ArgName {unArgName = "keyId"},ArgValue {unArgValue = "8FCB631E"})]}) (EncContent {unEncContent = "hQIMA3lu0PjDFmd8AQ//Q/1zSmyYch297WLFFjkXCCD4cN0O3ydN+UmEBE+J+8pHFirH3d/GOb8o1d/W1zuvL+7VCjm1S2VbreXr66OSj6Ox+0sVmW1IKN3wJLfpSXKVxXq8zcWrHIU+HCI6CsCc/7bEgnlEs8Cgf5rUwHr+3kaXuvIpvNM6bbhAHWDsoQo+NnzmeER6geK+SwjHO+hFC3QuI+18uDDGxeayn4+QRfKFkDfbNlaTdh6WhL7ltMXXY+WYpz5fV9jrbH+ZBf1XBhrJNmonGC32Cq7RnFLBqkUmEaUIanCHHoCwh9nE8IONY1YOqv/KdS9hNie3NdArtSS/cGI6HGjda5J+c+mKAyxMdvnTXXDmTrArTeveifRB9+wqMUct1d9WfIsZ1lgly0/uJHhPWsiNNHQ+6BVW90qOIVZfxcjjw0aBrG1QNng9xAJjwEVs+UJ8CoIDJ8XPuhHF5VLz4Qg7odpQpueAOhgtFaGyKaxxMzC49huMNrOx1tpcDpdhef93QOz2JnY/jfQIeq+kiaZF1SxjMoKZMXD1Xd0Yd73d3feqCE3FOrWVHm7NrU16ADk4Xa7m/kYzygaBo4Q+nDa2UFo1ExyD0Uqt8ZqjjoHpk+v9GWjISvPgGjVaHaS961OWR9HC1cu6S2L8tjwjrwOaHlI+fDTpgmfInHK/DaTZHCxN0IuYHdPSRQFKUKafXUo9Q+McvgJIo9RdMb6JAbPoLdep5Rda+WZTeser+MhkN77mcJ+ChrZSaWz2p9oH5QQwy/MO+UDTxgjsNfIFXw=="}))]}

ghci> tem'
"password = " `Txt` (ValRef {unValRef = ValName {unValueName = "password"}} `Ref` Nil)

ghci> encode tem'
"password = {{E|password}}"

ghci> Right tem'' <- runEitherT $ decryptTem gpgme meta tem'

ghci> tem''
"password = " `Txt` ("qwerty123!" `Txt` Nil)

ghci> encode tem''
"password = qwerty123!"
```

### Using `e` executable

```
$> cat file.config
username = dmalikov
password = qwerty123!

$> vim file.config       # wrap sensitive strings in a 'PlainValue's

$> cat file.config
username = {{P|username|gpgme|keyId = 8FCB631E|dmalikov}}
password = {{P|password|gpgme|keyId = 8FCB631E|qwerty123!}}

$> e enc file.config

$> cat file.config
username = {{E|username}}
password = {{E|password}}

$> cat .file.config.e
{
    "username": {
        "alg": "gpgme",
        "value": "hQIMA3lu0PjDFmd8AQ//bGsUrrpskpfHCwB68IKCfjZQ7p3GOGZXzTjEGGCynsEqAv/5DnkVB9XGGDbatgEBFcbiIb9f6bIcyzXZKF9CLq6+cxXyExqKTHornfrGjTUP2j2hf0bKbVFZ6DtADpQwquBiohoeUDVwQ2pVOKMkWfNkyv/Re1nIP2LBnxdbItn3C6mYSMb7FtLHxRj6EI8SuA83hmCu4Cu8mpsk08OHOXIerm9kzm63SsS6XGyq1JiE//5nb6cSG4SUgeV0d+WHX3IAmzapvqCQHXFfNPqbJj8NKjhk435gYk8i08FwOkP9+Ur7jjbzzQYvPD+0eFgrdUVIlSX00h1dyV8X99n0K41qNEgWY5AA22l4vK77To79qcvgJjwOENbv1RTrK3uYftcsg+8yg8SOyVQ4JBaBx84/hot9voC8aEImY098KbLla73weSwcb5p5gwJvK33xeT4FvgD0IJHJhmkNO5U6xp/hiAqPUdDseXCO3QjIocINfiH2sxJxbbpQ01Mx7ernLz1vFCxCnt1CjIvaCtDpmaWWbx8KVnMz/QYlo8hpT0JGu7DgETujJDkWRWZx3opF61bn2PW+Nh552kmnizAJl3ImZAmqPp1f1VKVU9/BAXNNpQfXrE129JUT7Z5h11sqcQummultPg/BogPN8WLneMFqGzL9kfQtGWtySQWJDWnSQwEBc2V+E1WzBHcUvm5t4A3VHR/VT1U65/dstfeZgY6W0Xc/nkt0KL0i3yXOVkRtvncyDlceecNEHWAUenTEIOAPsfM=",
        "args": {
            "keyId": "8FCB631E"
        }
    },
    "password": {
        "alg": "gpgme",
        "value": "hQIMA3lu0PjDFmd8AQ//Zc2ycATx6ZdMjG15yNSz8CBjvj3afodyPJuFSWoelagn5m0k4YgfphD1ylzzESKNd9e0UJs/DDjGcEdaeg0KCytMmxDrz1+B9J2fmeiKzXIWi/wPgHjxeaxtTpnc+TlewCvO2dyGYvOCMNM3RbXKISpnYfT0Zt8wc/4V3NGiX7uD0dUq9jnyyH5vvuOEyJzEQ/BhJPgCeGFBIQWn1i/udDqWtWPGVg7cFet4zlNLBfVgCmOxNzi0jO3hKguERQjhzzgMHlq4TYIvRyMj/92hw9fD3kbjefmOT97NSl7mTwztsEykKNShnsj4HQeNwuBbs84uprNBEk+Sv4tn2+WSdNDPhPJ2DSjnTRYm6gX+WqPeJwUAmaPBNlW05rJjWRXwF4gr2vydlEEwRgaz7ONB4c2bmcAggAaSJA5dodt04oZ5gd2+vSzUpw4GKNhhoGefX6PtPO6DHC243cnQw9ACWhc4N2KBqLZYlEfa0qd641Z5265SC1953Ug5lLD654rrAJbAkLsVdYrfEftCFL2D1QzP81aE7QAvDFkMCdn6BUNEVbaExz9a06H0ZbFsFgC4mrKUA/3u9Iziu5KxUJRbmW0Nsdaz+lw3JSWPBGslOf8weDuYOMcjWPTWDwmkV5LAGqnKU8dofVQ4F0/8Yvtz3Fitro5QJWJ0Pm+rMgeyCrnSRQHywUH7cnB1K7sD1Hgq/LyGq0lVvHnSM5JDnU+9H349h5m/ldBz8YUkZkcrPRwZK29acqqcTJwNRU8fkud0JjwU5vhsLw==",
        "args": {
            "keyId": "8FCB631E"
        }
    }
}

$> e dec file.config

$> cat file.config
username = dmalikov
password = qwerty123!
```

🎉

## How to add support for another encrypting mechanism? ##

Let's take a look at `encryptTem` and `decryptTem`:

```
encryptTem :: Algs -> Metadata -> Tem -> EitherT EError IO (Tem, Metadata)
decryptTem :: Algs -> Metadata -> Tem -> EitherT EError IO Tem
```

In order to encrypt/decrypt template with custom `Algs` you need to define one and just pass there.
Since `Algs` is a `Monoid`, you can use many of them: `aesgcm <> gpgme <> custom`.

`E.Algorithm.Dummy` provides an example of a simplest implementation of encrypting mechanism suitable for `Tem`.

```
dummy :: Algs
  dummy = algorithm (AlgName "dummy") (Cipher dummyCipher) (Decipher dummyDecipher)
 where
  dummyCipher _ (PlainContent c) = pure $ EncContent c
  dummyDecipher _ (EncContent c) = pure $ PlainContent c
```

`AlgName` and a couple of routines (`Cipher` and `Decipher`) is all that needed.

After that `encryptTem` could be used with it, like `encryptTem (dummy <> gpgme) mempty tem`.
