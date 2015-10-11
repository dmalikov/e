{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | 'Text' templating mechanism with a power of 'Data.ByteString.Encrypt'
module Data.Text.Encrypt.Template where

import           Control.E.Keys
import qualified Data.ByteString.Encrypt as E
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
encrypt :: TL.Text -> IO (Either EncryptTemplateError TL.Text)
encrypt = loopEncrypt TL.empty
 where

  loopEncrypt :: TL.Text -> TL.Text -> IO (Either EncryptTemplateError TL.Text)
  loopEncrypt buffer input | input == TL.empty = return (Right buffer)
                           | otherwise         = do
    let (plain, rest) = TL.breakOn "{{" input
    if (not ("{{" `TL.isPrefixOf` rest))
      then return (Right (buffer `TL.append` plain))
      else do
        let (toEncrypt, restRest) = TL.breakOn "}}" (TL.drop 2 rest)
        if (not ("}}" `TL.isPrefixOf` restRest))
          then return (Left (EncryptSyntaxError MissingClosingBraces))
          else do
            parseAndEncrypt toEncrypt >>= \case
              Left e          -> return (Left e)
              Right encrypted ->
                loopEncrypt (buffer `TL.append` plain `TL.append` encrypted) (TL.drop 2 restRest)

  -- | "keyId|value" -> "{{keyId|encryptedKeys|encryptedValue}}"
  parseAndEncrypt :: TL.Text -> IO (Either EncryptTemplateError TL.Text)
  parseAndEncrypt input = do
    let (keyId, value) = TL.breakOn "|" input
    if (not ("|" `TL.isPrefixOf` value))
      then return (Left (EncryptSyntaxError MissingPlainText))
      else
        getStorePath >>= lookupPublic (TL.unpack keyId) >>= \case
          Nothing        -> return (Left PublicKeyNotFound)
          Just publicKey ->
            E.encrypt publicKey (TL.toStrict (TL.drop 1 value)) >>= \case
              Left e                            -> return (Left (EncryptError e))
              Right (E.Encrypted keys ciphered) ->
                return . Right . TL.concat $
                  [  "{{"
                  , keyId
                  , "|"
                  , TL.fromStrict (TE.decodeUtf8 keys)
                  , "|"
                  , TL.fromStrict ciphered
                  , "}}"
                  ]

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
    if (not ("{{" `TL.isPrefixOf` rest))
      then return (Right (buffer `TL.append` plain))
      else do
        let (toDecrypt, restRest) = TL.breakOn "}}" (TL.drop 2 rest)
        if (not ("}}" `TL.isPrefixOf` restRest))
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
      keyId : encryptedKeys : ciphered : [] ->
        getStorePath >>= lookupPrivate (TL.unpack keyId) >>= \case
          Nothing         -> return (Left PrivateKeyNotFound)
          Just privateKey ->
            E.decrypt privateKey (E.Encrypted (TE.encodeUtf8 (TL.toStrict encryptedKeys)) (TL.toStrict ciphered)) >>= \case
              Left e          -> return (Left  (DecryptError e))
              Right decrypted -> return (Right (TL.fromStrict decrypted))
      _                                     -> return (Left (DecryptSyntaxError InvalidFormat))
