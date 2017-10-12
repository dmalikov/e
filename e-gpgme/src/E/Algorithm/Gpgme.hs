{-# Language OverloadedStrings #-}
module E.Algorithm.Gpgme (gpgme) where

import qualified Data.ByteString.Base64 as Base64
import Control.Monad.Trans.Either
import Data.Either.Combinators
import Data.Either.MoreCombinators
import Data.Text (pack)
import Data.Text.Encoding

import E

import Crypto.Gpgme.Encrypt

gpgme :: Algs
gpgme = algorithm (AlgName "gpgme") cipherGpg decipherGpg

cipherGpg :: Cipher
cipherGpg = Cipher $ \args value -> do
  let toCiph = EncContent . decodeUtf8 . Base64.encode
      value' = encodeUtf8 (unPlainContent value)
      getKeyId = hoistEither $ note "keyId is undefined" $ lookupArg "keyId" args
  keyId <- encodeUtf8 . unArgValue <$> getKeyId
  EitherT (mapBoth pack toCiph <$> encrypt homedir keyId value')

decipherGpg :: Decipher
decipherGpg = Decipher $ \_ value -> do
  let toPlain = PlainContent . decodeUtf8
  value' <- hoistEither $ mapLeft pack $ Base64.decode $ encodeUtf8 $ unEncContent value
  EitherT (mapBoth pack toPlain <$> decrypt homedir value')

homedir :: String
homedir = "~/.gnupg"
