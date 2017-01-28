{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE InstanceSigs              #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE StandaloneDeriving        #-}
-- | ByteString encryption routines
module Data.ByteString.Encrypt
  ( Encryptable(..)
  , Encrypted(..)
  , EncryptError(..)
  , DecryptError(..)
  , AESError(..)
  ) where

import qualified Codec.Crypto.RSA.Pure     as RSA
import           Control.Applicative       (liftA2)
import           Control.Arrow             (first, left, (***))
import           Control.Monad             (join)
import           Control.Monad.Morph       (hoist)
import           Control.Monad.Trans.State
import qualified Crypto.Cipher.AES         as AES
import           Crypto.Cipher.Types       (AuthTag (..))
import           Crypto.Random.DRBG        (CryptoRandomGen, GenError, genBytes)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base64    as Base64
import qualified Data.ByteString.Internal  as BSI (c2w, w2c)
import qualified Data.ByteString.Lazy      as BSL
import           Data.Text                 (Text)
import qualified Data.Text                 as T (pack)
import           Data.Text.Encoding        (decodeUtf8, encodeUtf8)

-- | Encrypted value.
data Encrypted e = Encrypted
  { _encryptedKeys :: BS.ByteString -- ^ AES-GCM input values (key, iv and tag) RSA-encrypted using given public key.
  , _ciphered      :: e             -- ^ AES-GCM-encrypted value.
  }

instance Eq e => Eq (Encrypted e) where
  (Encrypted k1 c1) == (Encrypted k2 c2) = k1 == k2 && c1 == c2

instance Show e => Show (Encrypted e) where
  show (Encrypted k c) = "Keys: " ++ BSI.w2c `fmap` BS.unpack k ++ ", Ciphered: " ++ (show c)

instance Functor Encrypted where
  fmap f (Encrypted k c) = Encrypted k (f c)

-- | Encryption error.
data EncryptError
  = EncryptRSAError RSA.RSAError -- ^ 'RSA.RSAError'.
  | EncryptGenError GenError     -- ^ Error in random bytes generation.
  | EncryptKeySizeError          -- ^ Size of public key is unappropriately small (less than a 64 bytes).
    deriving (Eq, Show)

-- | Decryption error.
data DecryptError
  = DecryptRSAError RSA.RSAError -- ^ 'RSA.RSAError'.
  | DecryptGenError GenError     -- ^ Error in random bytes generation.
  | DecryptAESError AESError     -- ^ Error in AES decryption.
  | DecryptBase64Error String    -- ^ Encoded keys is not a valid base64 encoded data.
    deriving (Eq, Show)

-- | AES error.
data AESError
  = TagMismatch -- ^ Authentication tag mismatch.
    deriving (Eq, Show)

-- | Unified interface for encryption routines.
class (Eq e, Show e) => Encryptable e where

  -- | Encrypt using given 'RSA.PublicKey'.
  encrypt :: CryptoRandomGen g => RSA.PublicKey -> e -> g -> Either EncryptError (Encrypted e, g)

  -- | Decrypt using given 'RSA.PrivateKey'.
  decrypt :: RSA.PrivateKey -> Encrypted e -> Either DecryptError e

  -- | Convert encrypted value to 'String'.
  showEnc :: Encrypted e -> String

  -- | Read encrypted value from 'String'.
  readEnc :: String -> Maybe (Encrypted e)


instance Encryptable BS.ByteString where
  encrypt = encryptBase
  decrypt = decryptBase

  showEnc (Encrypted ek c) = BSI.w2c `fmap` BS.unpack (BS.concat [ek, ".", c])

  readEnc string =
    case break (== '.') string of
      ([], _) -> Nothing
      (_, []) -> Nothing
      (ek, c) -> Just (Encrypted (BS.pack (map BSI.c2w ek)) (BS.pack (map BSI.c2w (tail c))))

instance Encryptable Text where
  encrypt key plain g = first (fmap decodeUtf8) `fmap` (encryptBase key (encodeUtf8 plain) g)

  decrypt privateKey encrypted = decodeUtf8 `fmap` (decryptBase privateKey (fmap encodeUtf8 encrypted))

  showEnc (Encrypted ek c) = BSI.w2c `fmap` BS.unpack (BS.concat [ek, ".", encodeUtf8 c])

  readEnc string =
    case break (== '.') string of
      ([], _) -> Nothing
      (_, []) -> Nothing
      (ek, c) -> Just (Encrypted (BS.pack (map BSI.c2w ek)) (T.pack (tail c)))

encryptBase :: forall g . CryptoRandomGen g =>
  RSA.PublicKey ->
  BS.ByteString ->
  g ->
  Either EncryptError (Encrypted BS.ByteString, g)
encryptBase publicKey plain = runStateT $ do
  (key, iv) <- StateT initialKeys
  let (ciphered, AuthTag tag) = AES.encryptGCM (AES.initAES key) iv "" plain
  encryptedKeys <- (left EncryptRSAError) `hoist` StateT (encryptKeys key iv tag)
  return (Encrypted (Base64.encode encryptedKeys) (Base64.encode ciphered))

    where

      initialKeys :: g -> Either EncryptError ((BS.ByteString, BS.ByteString), g)
      initialKeys = runStateT (liftA2 (,) bytes bytes)
        where bytes :: StateT g (Either EncryptError) BS.ByteString
              bytes = (left EncryptGenError) `hoist` StateT (genBytes 16)

      encryptKeys :: BS.ByteString -> BS.ByteString -> BS.ByteString -> g -> Either RSA.RSAError (BS.ByteString, g)
      encryptKeys key iv tag g = first BSL.toStrict <$> RSA.encrypt g publicKey (BSL.fromChunks [key `BS.append` iv `BS.append` tag])

decryptBase :: RSA.PrivateKey -> Encrypted BS.ByteString -> Either DecryptError BS.ByteString
decryptBase privateKey (Encrypted { _encryptedKeys = encryptedEncodedKeys, _ciphered = encodedCiphered}) = do
    encryptedKeys  <- left DecryptBase64Error $ Base64.decode encryptedEncodedKeys
    ciphered       <- left DecryptBase64Error $ Base64.decode encodedCiphered
    (key, iv, tag) <- left DecryptRSAError $ decryptKeys encryptedKeys
    let (plain, tagDecrypted) = AES.decryptGCM (AES.initAES key) iv "" ciphered
    case (AuthTag tag == tagDecrypted) of
      True  -> return plain
      False -> Left (DecryptAESError TagMismatch)

  where

    decryptKeys :: BS.ByteString -> Either RSA.RSAError (BS.ByteString, BS.ByteString, BS.ByteString)
    decryptKeys value = do
      keys <- RSA.decrypt privateKey (BSL.fromChunks [value])
      let (key, ivAndTag) = join (***) BSL.toStrict (BSL.splitAt 16 keys)
      let (iv, tag) = BS.splitAt 16 ivAndTag
      return (key, iv, tag)
