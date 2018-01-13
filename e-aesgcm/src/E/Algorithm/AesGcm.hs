{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}
-- | Assymetric encryption using RSA keys.
--
-- == Encryption
-- 1. @key@ <- (random 16 bytes)
--    @iv@ <- (random 16 bytes)
-- 2. (ciphered value, @tag@) <- [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) (@key@, @iv@, plain value)
-- 3. @s <- RSA.Enc (public key, "{base64 encoded @key@}.{base64 encoded @iv@}.{base64 encoded @tag@}")
-- 4. return "{@s@}.{base64 encoded ciphered value}"
--
-- == Decryption
-- 1. (@s@, @value@) <- input string is in "s.value" format
-- 2. @keys@ <- RSA.Dec (private key, @s@)
-- 3. (@key@, @iv@, @tag@) <- split @keys@ by 16 bytes
-- 4. (@plain@, @tag'@) <- AES-GCM.Dec (@key@, @iv@, base64 decode @value@)
-- 5. Ensure @tag@ == @tag'@

module E.Algorithm.AesGcm (aesgcm) where

import qualified Codec.Crypto.RSA.Pure as RSA
import Control.Monad.IO.Class
import Control.Monad.Trans.Except
import Crypto.Random.DRBG
import Data.ByteString.AesGcm
import Data.Either.MoreCombinators
import Data.Text (Text, pack, unpack)
import Data.Text.Encoding
import Text.Printf

import Codec.Crypto.RSA.AesGcmKeys
import E.Encrypt
import E.Template

aesgcm :: Algs
aesgcm = algorithm (AlgName "aesgcm") cipherAesGcm decipherAesGcm

cipherAesGcm :: Cipher
cipherAesGcm = Cipher $ \args value -> do
  let value' = encodeUtf8 (unPlainContent value)
      toCiph = EncContent . decodeUtf8 . fst
  g :: CtrDRBG <- liftIO newGenIO
  key <- getPublicKey =<< unArgValue <$> getKeyId args
  hoistEither $ mapBoth (pack . show) toCiph $ encrypt key value' g

decipherAesGcm :: Decipher
decipherAesGcm = Decipher $ \args value -> do
  let value' = encodeUtf8 (unEncContent value)
      toPlain = PlainContent . decodeUtf8
  key <- getPrivateKey =<< unArgValue <$> getKeyId args
  hoistEither $ mapBoth (pack . show) toPlain $ decrypt key value'

getKeyId :: Args -> ExceptT Text IO ArgValue
getKeyId = hoistEither . note "keyId is undefined" . lookupArg "keyId"

getPublicKey :: Text -> ExceptT Text IO RSA.PublicKey
getPublicKey (unpack -> keyId) =
  ExceptT (note notfound <$> lookupPublic keyId)
 where
  notfound = pack (printf "public key %d not found" keyId)

getPrivateKey :: Text -> ExceptT Text IO RSA.PrivateKey
getPrivateKey (unpack -> keyId) =
  ExceptT (note notfound <$> lookupPrivate keyId)
 where
  notfound = pack (printf "private key %s not found" keyId)
