{-# LANGUAGE LambdaCase #-}
-- | Key management
module Codec.Crypto.RSA.AesGcmKeys
  ( lookupPrivate
  , lookupPublic
  ) where

import qualified Codec.Crypto.RSA.Pure as RSA
import System.Directory (doesFileExist, getHomeDirectory)
import System.Environment (lookupEnv)
import System.FilePath ((</>))

-- | 'FilePath' of a key store.
-- Return a value of @$E_KEYS_STORE@ environment variable if defined.
-- Return @~/.encrypt-keys@ otherwise.
--
-- Note: this method isn't supposed to create such directory if it doesn't exist.
getStorePath :: IO FilePath
getStorePath =
  lookupEnv "E_KEYS_STORE" >>= \case
    Just path -> pure path
    Nothing   -> (</> ".encrypt-keys") `fmap` getHomeDirectory

-- | Lookup private key from key store.
lookupPrivate :: String -- ^ Key id.
              -> IO (Maybe RSA.PrivateKey)
lookupPrivate keyId = do
  filename <- (</> keyId ++ ".private") <$> getStorePath
  doesFileExist filename >>= \case
    True  -> Just . read <$> readFile filename
    False -> pure Nothing

-- | Lookup public key from key store.
lookupPublic :: String -- ^ Key id.
             -> IO (Maybe RSA.PublicKey)
lookupPublic keyId = do
  filename <- (</> keyId ++ ".public") <$> getStorePath
  doesFileExist filename >>= \case
    True  -> Just . read <$> readFile filename
    False -> pure Nothing
