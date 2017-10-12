{-# LANGUAGE OverloadedStrings #-}
-- | Assymetric encryption using RSA keys.
--
-- == Encryption
-- 1. @key@ <- (random 16 bytes)
-- 2. @iv@ <- (random 16 bytes)
-- 3. (ciphered value, @tag@) <- [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) (@key@, @iv@, plain value)
-- 4. @s <- RSA.Enc (public key, "{base64 encoded @key@}.{base64 encoded @iv@}.{base64 encoded @tag@}")
-- 5. return "{@s@}.{base64 encoded ciphered value}"
--
-- == Decryption
-- 1. (@s@, @value@) <- input string is in "s.value" format
-- 2. @keys@ <- RSA.Dec (private key, @s@)
-- 3. (@key@, @iv@, @tag@) <- split @keys@ by 16 bytes
-- 4. (@plain@, @tag'@) <- AES-GCM.Dec (@key@, @iv@, base64 decode @value@)
-- 5. Ensure @tag@ == @tag'@
module Data.ByteString.AesGcm
  (
  -- * Encrypt / Decrypt
    encrypt
  , decrypt
  -- * Encrypted value container
  , Encrypted(..)
  , showEnc
  , readEnc
  -- * Exceptions
  , EncryptError(..)
  , DecryptError(..)
  ) where

import qualified Codec.Crypto.RSA.Pure     as RSA
import           Control.Applicative       (liftA2)
import           Control.Arrow             (first, left, (***))
import           Control.Error
import           Control.Monad             (join)
import           Control.Monad.Morph       (hoist)
import           Control.Monad.Trans.State
import qualified Crypto.Cipher.AES         as AES
import           Crypto.Cipher.Types       (AuthTag (..))
import           Crypto.Random.DRBG
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base64    as Base64
import           Data.ByteString.Internal  (c2w)
import qualified Data.ByteString.Lazy      as BSL

-- | Encryption error.
data EncryptError
  = EncryptRSAError RSA.RSAError -- ^ 'RSA.RSAError'.
  | EncryptGenError GenError     -- ^ Error in random bytes generation.
  | EncryptKeySizeError          -- ^ Size of public key is unappropriately small (less than a 64 bytes).
    deriving (Eq,Show)

-- | Decryption error.
data DecryptError
  = DecryptRSAError RSA.RSAError -- ^ 'RSA.RSAError'.
  | DecryptGenError GenError     -- ^ Error in random bytes generation.
  | DecryptAESError AESError     -- ^ Error in AES decryption.
  | DecryptBase64Error String    -- ^ Encoded keys is not a valid base64 encoded data.
  | DecryptFormatError           -- ^ Encrypted value is not in proper format.
    deriving (Eq,Show)

-- | AES error.
data AESError
  = TagMismatch -- ^ Authentication tag mismatch.
    deriving (Eq,Show)

-- | Encrypted value.
data Encrypted = Encrypted
  { _encryptedKeys :: ByteString -- ^ AES-GCM input values (key, iv and tag) RSA-encrypted using given public key.
  , _ciphered      :: ByteString -- ^ AES-GCM-encrypted value.
  } deriving (Eq,Show)

-- | Internal machinery of 'Encrypted' -> 'ByteString' correspondence.
showEnc :: Encrypted -> ByteString
showEnc (Encrypted ek c) = BS.concat [ek, ".", c]

-- | Internal machinery of 'Encrypted' <- 'ByteString' correspondence.
readEnc :: ByteString -> Maybe Encrypted
readEnc string = let (ek, c) = BS.break (== c2w '.') string in
  if ek == "" || c == ""
     then Nothing
     else Just (Encrypted ek (BS.tail c))

-- | Encrypt 'ByteString' with 'RSA.PublicKey'.
encrypt :: CryptoRandomGen g => RSA.PublicKey -> ByteString -> g -> Either EncryptError (ByteString, g)
encrypt k i g = first showEnc <$> encryptBase k i g

-- | Decrypt 'ByteString' with 'RSA.PrivateKey'.
decrypt :: RSA.PrivateKey -> ByteString -> Either DecryptError ByteString
decrypt k i = decryptBase k =<< note DecryptFormatError (readEnc i)

encryptBase :: CryptoRandomGen g => RSA.PublicKey -> ByteString -> g -> Either EncryptError (Encrypted, g)
encryptBase publicKey plain = runStateT $ do
  (key, iv) <- StateT initialKeys
  let (ciphered, AuthTag tag) = AES.encryptGCM (AES.initAES key) iv "" plain
  encryptedKeys <- left EncryptRSAError `hoist` StateT (encryptKeys key iv tag)
  return (Encrypted (Base64.encode encryptedKeys) (Base64.encode ciphered))
 where
  initialKeys :: CryptoRandomGen g => g -> Either EncryptError ((ByteString, ByteString), g)
  initialKeys = runStateT (liftA2 (,) bytes bytes)
   where
    bytes :: CryptoRandomGen g => StateT g (Either EncryptError) ByteString
    bytes = left EncryptGenError `hoist` StateT (genBytes 16)

  encryptKeys :: CryptoRandomGen g => ByteString -> ByteString -> ByteString -> g -> Either RSA.RSAError (ByteString, g)
  encryptKeys key iv tag g = first BSL.toStrict <$> RSA.encrypt g publicKey (BSL.fromChunks [key `BS.append` iv `BS.append` tag])

decryptBase :: RSA.PrivateKey -> Encrypted -> Either DecryptError ByteString
decryptBase privateKey Encrypted { _encryptedKeys = encryptedEncodedKeys, _ciphered = encodedCiphered} = do
    encryptedKeys  <- left DecryptBase64Error $ Base64.decode encryptedEncodedKeys
    ciphered       <- left DecryptBase64Error $ Base64.decode encodedCiphered
    (key, iv, tag) <- left DecryptRSAError $ decryptKeys encryptedKeys
    let (plain, tagDecrypted) = AES.decryptGCM (AES.initAES key) iv "" ciphered
    if AuthTag tag == tagDecrypted
      then return plain
      else Left (DecryptAESError TagMismatch)
 where
  decryptKeys :: ByteString -> Either RSA.RSAError (ByteString, ByteString, ByteString)
  decryptKeys value = do
    keys <- RSA.decrypt privateKey (BSL.fromChunks [value])
    let (key, ivAndTag) = join (***) BSL.toStrict (BSL.splitAt 16 keys)
    let (iv, tag) = BS.splitAt 16 ivAndTag
    return (key, iv, tag)
