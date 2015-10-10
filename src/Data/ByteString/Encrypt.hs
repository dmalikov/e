{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE InstanceSigs              #-}
{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE StandaloneDeriving        #-}
-- | ByteString encryption routines.
module Data.ByteString.Encrypt
  ( Encryptable(..)
  , Encrypted(..)
  , EncryptError(..)
  , DecryptError(..)
  ) where


import qualified Codec.Crypto.RSA.Pure    as RSA
import           Control.Arrow            ((***))
import           Control.Monad            (join)
import qualified Crypto.Cipher.AES        as AES
import           Crypto.Cipher.Types      (AuthTag (..))
import           Crypto.Random.DRBG       (CtrDRBG, GenError, genBytes, newGenIO)
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Base64   as Base64
import qualified Data.ByteString.Internal as BSI (c2w, w2c)
import qualified Data.ByteString.Lazy     as BSL
import           Data.Text                (Text)
import qualified Data.Text                as T (pack)
import           Data.Text.Encoding       (decodeUtf8, encodeUtf8)

-- | Encrypted value.
data Encrypted e = (Eq e, Encryptable e, Show e) => Encrypted
  { _encryptedKeys :: BS.ByteString -- ^ AES-GCM input values (key, iv and tag) RSA-encrypted using given public key
  , _ciphered      :: e             -- ^ AES-GCM-encrypted value
  }

instance Eq (Encrypted e) where
  (Encrypted k1 c1) == (Encrypted k2 c2) = k1 == k2 && c1 == c2

instance Show (Encrypted e) where
  show (Encrypted k c) = "Keys: " ++ BSI.w2c `fmap` BS.unpack k ++ ", Ciphered: " ++ (show c)

deriving instance Eq RSA.RSAError -- TODO: get rid of it

-- | Encryption error.
data EncryptError
  = EncryptRSAError RSA.RSAError -- ^ 'RSA.RSAError'.
  | EncryptGenError GenError     -- ^ Something happen during random bytes generation.
  | EncryptKeySizeError          -- ^ Size of public key is unappropriately small (less than a 64 bytes).
    deriving (Eq, Show)

-- | Decryption error.
data DecryptError
  = DecryptRSAError RSA.RSAError -- ^ 'RSA.RSAError'.
  | DecryptGenError GenError     -- ^ Something happen during random bytes generation.
  | DecryptAESError              -- ^ Decrypted tag doesn't match the original one. TODO: well, name it properly than.
  | DecryptBase64Error String    -- ^ Encoded keys is not a valid base64 encoded data.
    deriving (Eq, Show)

-- | Unified interface for encryption routines.
class (Eq e, Show e) => Encryptable e where

  -- | Encrypt using given 'RSA.PublicKey'.
  encrypt :: RSA.PublicKey -> e -> IO (Either EncryptError (Encrypted e))

  -- | Decrypt using given 'RSA.PrivateKey'.
  decrypt :: RSA.PrivateKey -> Encrypted e -> IO (Either DecryptError e)

  -- | Convert encrypted value to 'String'.
  showEnc :: Encrypted e -> String

  -- | Read encrypted value from 'String'.
  readEnc :: String -> Maybe (Encrypted e)

encryptBase :: RSA.PublicKey -> BS.ByteString -> IO (Either EncryptError (Encrypted BS.ByteString))
encryptBase publicKey plain = do
  if (RSA.public_size publicKey) < 64
    then return (Left EncryptKeySizeError)
    else do
      generateBytes >>= \case
        Left e    -> return (Left (EncryptGenError e))
        Right key -> do
          generateBytes >>= \case
            Left e   -> return (Left (EncryptGenError e))
            Right iv -> do
              let (ciphered, (AuthTag tag)) = AES.encryptGCM (AES.initAES key) iv "" plain
              encryptKeys key iv tag >>= \case
                Left e              -> return (Left (EncryptRSAError e))
                Right encryptedKeys -> return (Right (Encrypted (Base64.encode encryptedKeys) (Base64.encode ciphered)))

  where
    generateBytes :: IO (Either GenError BS.ByteString)
    generateBytes = do
      gen <- newGenIO :: IO CtrDRBG
      return (fst <$> genBytes 16 gen)

    encryptKeys :: BS.ByteString -> BS.ByteString -> BS.ByteString -> IO (Either RSA.RSAError BS.ByteString)
    encryptKeys key iv tag = do
      gen <- newGenIO :: IO CtrDRBG
      return (BSL.toStrict . fst <$> RSA.encrypt gen publicKey (BSL.fromChunks [key `BS.append` iv `BS.append` tag]))


decryptBase :: RSA.PrivateKey -> Encrypted BS.ByteString -> IO (Either DecryptError BS.ByteString)
decryptBase privateKey (Encrypted {_encryptedKeys = encryptedEncodedKeys, _ciphered = encodedCiphered }) =
  case Base64.decode encryptedEncodedKeys of
    Left e              -> return (Left (DecryptBase64Error e))
    Right encryptedKeys ->
      case Base64.decode encodedCiphered of
        Left e         -> return (Left (DecryptBase64Error e))
        Right ciphered ->
          case decryptKeys encryptedKeys of
            Left e               -> return (Left (DecryptRSAError e))
            Right (key, iv, tag) -> do
              let (plain, tagDecrypted) = AES.decryptGCM (AES.initAES key) iv "" ciphered
              if (AuthTag tag /= tagDecrypted)
                then return (Left DecryptAESError)
                else return (Right plain)

  where

    decryptKeys :: BS.ByteString -> Either RSA.RSAError (BS.ByteString, BS.ByteString, BS.ByteString)
    decryptKeys value = do
      keys <- RSA.decrypt privateKey (BSL.fromChunks [value])
      let (key, ivAndTag) = join (***) BSL.toStrict (BSL.splitAt 16 keys)
      let (iv, tag) = BS.splitAt 16 ivAndTag
      return (key, iv, tag)

instance Encryptable BS.ByteString where
  encrypt = encryptBase
  decrypt = decryptBase

  showEnc (Encrypted ek c) = BSI.w2c `fmap` BS.unpack (BS.concat [ek, ".", c])

  readEnc string = case break (== '.') string of
                     ([], _) -> Nothing
                     (_, []) -> Nothing
                     (ek, c) -> Just (Encrypted (BS.pack (map BSI.c2w ek)) (BS.pack (map BSI.c2w (tail c))))

instance Encryptable Text where
  encrypt key plain = do
    encryptBase key (encodeUtf8 plain) >>= \case
      Left e                          -> return (Left e)
      Right (Encrypted keys ciphered) -> return (Right (Encrypted keys (decodeUtf8 ciphered)))

  decrypt privateKey (Encrypted keys ciphered) = do
    decryptBase privateKey (Encrypted keys (encodeUtf8 ciphered)) >>= \case
      Left e  -> return (Left e)
      Right v -> return (Right (decodeUtf8 v))

  showEnc (Encrypted ek c) = BSI.w2c `fmap` BS.unpack (BS.concat [ek, ".", encodeUtf8 c])

  readEnc string = case break (== '.') string of
                     ([], _) -> Nothing
                     (_, []) -> Nothing
                     (ek, c) -> Just (Encrypted (BS.pack (map BSI.c2w ek)) (T.pack (tail c)))
