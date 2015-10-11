{-# LANGUAGE LambdaCase #-}
-- | Key management
module Control.E.Keys.Internal where

import qualified Codec.Crypto.RSA.Pure as RSA
import           Control.Monad         (when)
import           Crypto.Random.DRBG    (CtrDRBG, newGenIO)
import qualified Data.HashMap.Strict   as H
import           System.Directory      (createDirectory, doesDirectoryExist, doesFileExist, getDirectoryContents, getHomeDirectory, removeFile)
import           System.Environment    (lookupEnv)
import           System.FilePath       (takeFileName, (</>))
import           System.Random

-- | 'FilePath' of a key store.
-- Return a value of @$E_KEYS_STORE@ environment variable if defined.
-- Return @~/.encrypt-keys@ otherwise.
--
-- Note: this method isn't supposed to create such directory if it doesn't exist.
getStorePath :: IO FilePath
getStorePath =
  lookupEnv "E_KEYS_STORE" >>= \case
    Just path -> return path
    Nothing   -> (</> ".encrypt-keys") `fmap` getHomeDirectory

-- | Lookup private key from key store.
lookupPrivate :: String   -- ^ Key id.
              -> FilePath -- ^ Key store 'FilePath'.
              -> IO (Maybe RSA.PrivateKey)
lookupPrivate keyId store = let filename = store </> keyId ++ ".private"
  in
    doesFileExist filename >>= \case
      True  -> Just . read <$> readFile filename
      False -> return Nothing

-- | Lookup public key from key store.
lookupPublic :: String   -- ^ Key id.
             -> FilePath -- ^ Key store 'FilePath'.
             -> IO (Maybe RSA.PublicKey)
lookupPublic keyId store = let filename = store </> keyId ++ ".public"
  in
    doesFileExist filename >>= \case
      True  -> Just . read <$> readFile filename
      False -> return Nothing

-- | Any possible state of a given key's presence.
data KeyPresence
  = Private -- ^ Only private key exists.
  | Public  -- ^ Only public key exists.
  | Both    -- ^ Both private and public keys exist.
  | None    -- ^ Neither private nor public keys exist.
    deriving (Eq, Show)

-- | ಥ_ಥ.
instance Monoid KeyPresence where
  mempty = None

  mappend Both    _       = Both
  mappend _       Both    = Both
  mappend None    x       = x
  mappend x       None    = x
  mappend Private Public  = Both
  mappend Public  Private = Both
  mappend x       _       = x

-- | Does this 'KeyPresence' include public key?
hasPublic :: KeyPresence -> Bool
hasPublic Public = True
hasPublic Both   = True
hasPublic _      = False

-- | Does this 'KeyPresence' include private key?
hasPrivate :: KeyPresence -> Bool
hasPrivate Private = True
hasPrivate Both    = True
hasPrivate _       = False

-- | Read keys from a given store.
readStore :: FilePath                          -- ^ Key store 'FilePath'.
          -> IO (H.HashMap String KeyPresence) -- ^ Mapping from a given keyId to 'KeyPresence'
readStore s = foldl addKey H.empty <$> filter (\x -> x /= "." || x /= "..") <$> getDirectoryContents s
 where
  addKey oldStore file = let
    parse filename =
      case break (== '.') (takeFileName filename) of
        (keyId, '.':"public")  -> Just (keyId, Public)
        (keyId, '.':"private") -> Just (keyId, Private)
        _                      -> Nothing
    in case parse file of
         Just (keyId, keyType) -> H.insertWith mappend keyId keyType oldStore
         Nothing               -> oldStore

-- | List all keys in key store.
list :: IO ()
list = do
  s <- getStorePath
  doesDirectoryExist s >>= \exist ->
    if (not exist)
      then error (s ++ " does not exist")
      else readStore s >>= \s' -> mapM_ (uncurry showKeys) (H.toList s')
 where
  showKeys keyId keyPresence = putStrLn (keyId ++ " [" ++ (toString (hasPrivate keyPresence)) ++ "private,"
                                                       ++ (toString (hasPublic  keyPresence)) ++ "public]")
  toString bool = if bool then "+" else "-"

-- | Generate keypair with a given keyId.
generate :: Maybe String -- ^ If it is 'Nothing' keyId will be chosen randomly.
         -> IO ()
generate maybeKeyId = do
  case maybeKeyId of
    Just keyId -> generate' keyId
    Nothing    -> generate' =<< randomStr 10
 where
  generate' :: String -> IO ()
  generate' keyId = do
    gen <- newGenIO :: IO CtrDRBG
    let Right (publicKey, privateKey, _) = RSA.generateKeyPair gen 4096
    keyStore <- getStorePath
    doesDirectoryExist keyStore >>= \exist -> when (not exist) (createDirectory keyStore)
    let pubfp  = keyStore </> keyId ++ ".public"
    let privfp = keyStore </> keyId ++ ".private"
    writeFileIfNotExist pubfp (show publicKey) $ error (pubfp ++ " file already exists")
    putStrLn ("public key saved to " ++ pubfp)
    writeFileIfNotExist privfp (show privateKey) $ error (privfp ++ " file already exists")
    putStrLn ("private key saved to " ++ privfp)

  writeFileIfNotExist :: FilePath -> String -> IO () -> IO ()
  writeFileIfNotExist filename content onExists =
    doesFileExist filename >>= \case
      True  -> onExists
      False -> writeFile filename content

-- | Remove keypair with a given keyId from key store.
removeKey :: String -> IO ()
removeKey keyId = do
  putStrLn ("Removing key <" ++ keyId ++ ">")
  privateKeyFile <- (</> keyId ++ ".private") <$> getStorePath
  publicKeyFile  <- (</> keyId ++ ".public")  <$> getStorePath
  whenM (doesFileExist privateKeyFile) (removeFile privateKeyFile)
  whenM (doesFileExist publicKeyFile)  (removeFile publicKeyFile)
 where
  whenM :: IO Bool -> IO () -> IO ()
  whenM monadBool action = do
    bool' <- monadBool
    when bool' action

-- | Generate random string.
randomStr :: Int -- ^ Length of generated string.
          -> IO String
randomStr n = take n . randomRs ('a','z') <$> newStdGen
