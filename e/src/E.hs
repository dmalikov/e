{-| == Goal
   Hide sensitive data inside text files in a readable and compact manner.

  == Requirements

* Support various encryption/key-storing mechanisms (per encrypted value)

* Adding new portion of secrets to already encrypted text file does not modify previously encrypted values

* Only sensitive data is hidden, the rest is left intact.

* Ciphered values should not be part of the file (in order to make it readable and compact).

* Same ciphered value could be referenced many times.

* [TODO] Same ciphered value could be referenced in many files.


  == Solution

Assume there is a file @config@ containing some sensitive data.

@
host = "localhost"
user = "foobar"
password = "5fce4e0edf2242e981f799b1d8e0dc62"
@

In order to hide sensitive data it's need to be wrapped with a @Plain value@ identifier.

@
host = "localhost"
user = "{{P|username|gpgme|kid = keyId|foobar}}"
password = "{{P|password|gpgme|kid = keyId|5fce4e0edf2242e981f799b1d8e0dc62}}"
@

For instance, @{{P|username|gpgme|kid = keyId|foobar}}@ means that it's a variable @username@ with a __P__lain value __foobar__ that should be encrypted with __gpgme__ algorithm, and there are some arguments (@kid = keyId@) that would be needed during encryption process.


After things are set up, encryption could be done.

Here is how @config@ file look like after encryption:

@
host = "localhost"
user = "{{E|username}}"
password = "{{E|password}}"
@

Metadata file with encrypted values @.config.e@:

@
{
    "username": {
        "alg": "gpgme",
        "args": {
          "kid": "keyId"
        },
        "value": "CNMoJrL5jnbgw4UM60Ht+NXoOtdgk8iStAB8D6JAnZHyz6Z7YfdoNs4EyoqMbBhRDlRRpakbtfiIvH1GlcOt7RzQfHzv+ZNQkU2o12na/X6uZVw+abJYjpsG50wpkeE8h8W08htNE1JEAsgomojIlRYM973H1aoPqkgS+75fyvdadFVB9yTnSV6qOBwFJOi62wrrHpNCoJMNJMf6OX5O/BTaXFSxSPXQc15v6SXh5ryQb/Oh0VCZdzkAF4UMAi/Sl84WMh/M4XR/c8TfcAW3MG6v9ToWX+hPUq+jD14oZpvqWc8lNHMWibcoTt8fxm5BebvX7+8x+L0JA0RYdeSZx/Fww0QxMAO46slc6BSRPV78ULuS6HAOfUN5zEIXV9e9ru+4sEa+myOJPoNR2fEbxPpYAbUe0UZjKn1Z5iuVtihhnY+gx2alv6Aiv45sG+Xv7qCdnXbW6I0EuI6eOEKeUgP2FHAffRdGkk/5Qbc4q74GgjDJPVAZOHppI7QMx3z89ndBEWZ6bTUEkNVBQqy8vusgogoIf/OWXrbCr4nwSyx1G3pvNnLJrbt4I4udaSfj8qKWJoZX8BvNl4yJBy5P1XW+E1WJX4pp74oKaI6L9QXrV5HECzec7KwA9CsTmigSZmKasgI5V62q1HiGyfygz7H/Pwf7EykW0vgq4Qs9R1U=|lvUD"
    },
    "password": {
        "alg": "gpgme",
        "args": {
          "kid": "keyId"
        },
        "value": "NcUeEoRHrl1LrVsYml9R8oZVAaYNv2rCcYLF2RwPHD9i62Xrf9tBiyQLjGSmScGJlbubztHh6ZHEeMv2zEELNMt6N0yc7tGsI4s7aSxVs5LfibwGeKGelZUgv41Fi/F32SvTTDepL3M20PlPpE/wp1lPv8WewWsa/kPJz6m63x2MinF1l13UvNQ7i61FPkjdYBclmM1oiqaztqPYG6uBINm1We/oKvWe3kEsDfRh4Gwg4J5YSe8rjNwM1wNzrNsj4+FI3abav9TpqQAcG/t261TdB3ocdt3L6/5Cd+KLqnIhDEpCwBUlt747bo4XNXH4Z4Tzpclh/a4CzNW+jyoDSo6Yddt6wwNn+75NKlkPIOOt2JorZiTFA1MJ97imRIiAfbaz8yzs3WC1lr/uPtaP2rmslHdGIC9uprrMp7hBoyeYTEwy5QN5lWuJzGq9siKSChrXTy/KP6eSQiL6WIN1BquDigOio8N1ezjokkRZZo8ijDERIYciZZuMfEW3kbDZIFx0/cBgeM/5kfpkK8lCmuMeXM9WxFhNGKkOgrlAFzbukuOqxnOxlHvyrwb7qwWc4zmvz9R+O0twwU8sJjqoDIUliX9nZ/mAGkG9rKwZhY3AbWN1QAF/yPY2+2FfVXm7/7ZN7x5GCXYQ86ov+yl976mk5jGqyg5CHKYA9673ruA=|VpMaDn9r0II="
    }
}
@


Encrypted file @config@ could be decrypted back using the same metadata:

@
host = "localhost"
user = "foo"
password = "5fce4e0edf22"
@

🎉

-}

module E
  (
  -- * Template - representation of an encrypted or to-be-encrypted content.
    module E.Template
  -- * Metatada - ciphered values store
  , module E.Metadata
  -- * Cipher values from 'Tem' using 'Metadata'
  , module E.Encrypt
  -- * Cipher actions on the filesystem
  , module E.Action
  -- * Simplest instance of Algs
  , module E.Algorithm.Dummy
  -- * Errors
  , module E.Describe
  -- * Reexports
  , pack
  , module Control.Monad.Trans.Either
  ) where

import E.Action
import E.Algorithm.Dummy
import E.Encrypt
import E.Metadata
import E.Template
import E.Describe

import Data.Text (pack)
import Control.Monad.Trans.Either

{-# ANN module ("HLint: ignore Use import/export shortcut" :: String) #-}
