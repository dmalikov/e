{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | 'Text' templating mechanism with a power of 'Data.ByteString.Encrypt'
module Data.Text.Template.Encrypt where

import           Control.E.Keys
import           Control.Monad.Except
import           Control.Monad.State
import           Crypto.Random.DRBG      (CryptoRandomGen)
import qualified Data.ByteString.Encrypt as E
import qualified Data.Text               as T
import qualified Data.Text.Encoding      as TE
import qualified Data.Text.Lazy          as TL

-- | Templating error occurred during encryption.
data EncryptTemplateError
  = EncryptSyntaxError SyntaxError -- ^ Malformed syntax.
  | PublicKeyNotFound              -- ^ Given public key doesn't exist in key store.
  | EncryptError E.EncryptError    -- ^ Internal 'E.EncryptError'.
    deriving (Eq, Show)

-- | Templating error occurred during decryption.
data DecryptTemplateError
  = PrivateKeyNotFound             -- ^ Given private key doesn't exist in key store.
  | DecryptSyntaxError SyntaxError -- ^ Malformed syntax.
  | DecryptError E.DecryptError    -- ^ Internal 'E.DecryptError'.
    deriving (Eq, Show)

-- | Syntax error.
data SyntaxError
  = MissingClosingBraces -- ^ Closing braces is missed.
  | MissingPlainText     -- ^ Plain text part is missed.
  | InvalidFormat        -- ^ Invalid format.
    deriving (Eq, Show)

-- | Encrypt given 'TL.Text'.
--
-- @
--     > encrypt "This is {{id01|nice}}!"
--     "This is {{id01|\<some hash\>|\<some hash\>}}!"
-- @
encrypt :: forall g . CryptoRandomGen g => TL.Text -> g -> IO (Either EncryptTemplateError TL.Text, g)
encrypt = loopEncrypt TL.empty

 where

  loopEncrypt :: TL.Text -> TL.Text -> g -> IO (Either EncryptTemplateError TL.Text, g)
  loopEncrypt = \b i -> (runStateT . runExceptT) (go b i)
    where
      go :: TL.Text -> TL.Text -> ExceptT EncryptTemplateError (StateT g IO) TL.Text
      go buffer input =
        if input == TL.empty
          then return buffer
          else do
            let (plain, rest) = TL.breakOn "{{" input
            if not ("{{" `TL.isPrefixOf` rest)
              then return (buffer `TL.append` plain)
              else do
                let (toEncrypt, restRest) = TL.breakOn "}}" (TL.drop 2 rest)
                if not ("}}" `TL.isPrefixOf` restRest)
                  then throwError $ EncryptSyntaxError MissingClosingBraces
                  else
                    parseAndEncrypt toEncrypt >>= \encrypted ->
                      go (buffer `TL.append` plain `TL.append` encrypted) (TL.drop 2 restRest)

  -- | "keyId|value" -> "{{keyId|encryptedKeys|encryptedValue}}"
  parseAndEncrypt :: TL.Text -> ExceptT EncryptTemplateError (StateT g IO) TL.Text
  parseAndEncrypt input = do
    let (keyId, value) = TL.breakOn "|" input
    if not ("|" `TL.isPrefixOf` value)
      then throwError $ EncryptSyntaxError MissingPlainText
      else (ExceptT . StateT) $ \g -> do
        p <- lookupPublic (TL.unpack keyId) =<< getStorePath
        case p of
          Nothing -> return (Left PublicKeyNotFound, g)
          Just key ->
            case E.encrypt key (TL.toStrict (TL.drop 1 value)) g of
              Left e          -> return (Left (EncryptError e), g)
              Right (enc, g') -> return (Right (formatEncrypted keyId enc), g')

       where

        formatEncrypted :: TL.Text -> E.Encrypted T.Text -> TL.Text
        formatEncrypted keyId (E.Encrypted keys ciphered) = TL.concat [  "{{" , keyId , "|" , TL.fromStrict (TE.decodeUtf8 keys) , "|" , TL.fromStrict ciphered , "}}" ]


-- | Decrypt given 'TL.Text'.
--
-- @
--     > decrypt "This is {{id01|\<some hash\>|\<some hash\>}}!"
--     "This is nice!"
-- @
decrypt :: TL.Text -> IO (Either DecryptTemplateError TL.Text)
decrypt = loopDecrypt TL.empty
 where
  loopDecrypt :: TL.Text -> TL.Text -> IO (Either DecryptTemplateError TL.Text)
  loopDecrypt buffer input = do
    let (plain, rest) = TL.breakOn "{{" input
    if not ("{{" `TL.isPrefixOf` rest)
      then return (Right (buffer `TL.append` plain))
      else do
        let (toDecrypt, restRest) = TL.breakOn "}}" (TL.drop 2 rest)
        if not ("}}" `TL.isPrefixOf` restRest)
          then return (Left (DecryptSyntaxError MissingClosingBraces))
          else
            parseAndDecrypt toDecrypt >>= \case
              Left e          -> return (Left e)
              Right decrypted ->
                loopDecrypt (buffer `TL.append` plain `TL.append` decrypted) (TL.drop 2 restRest)


  -- | "keyId|encryptedKeys|ciphered" -> "decrypted"
  parseAndDecrypt :: TL.Text -> IO (Either DecryptTemplateError TL.Text)
  parseAndDecrypt input =
    case TL.splitOn "|" input of
      [keyId, encryptedKeys, ciphered] ->
        getStorePath >>= lookupPrivate (TL.unpack keyId) >>= \case
          Nothing         -> return (Left PrivateKeyNotFound)
          Just privateKey ->
            case E.decrypt privateKey (E.Encrypted (TE.encodeUtf8 (TL.toStrict encryptedKeys)) (TL.toStrict ciphered)) of
              Left e          -> return (Left  (DecryptError e))
              Right decrypted -> return (Right (TL.fromStrict decrypted))
      _                                     -> return (Left (DecryptSyntaxError InvalidFormat))
