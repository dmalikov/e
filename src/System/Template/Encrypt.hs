{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | 'FilePath' templating mechanism with a power of 'Data.Text.Template.Encrypt'.
module System.Template.Encrypt
  ( encrypt
  , decrypt
  , EncryptSystemError(..)
  , DecryptSystemError(..)
  , FSError(..)
  ) where

import           Control.Monad              (unless)
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Except
import           Crypto.Random.DRBG
import qualified Data.Text.Lazy.IO          as TLIO
import qualified Data.Text.Template.Encrypt as Template
import           System.Directory           (doesDirectoryExist, doesFileExist)
import           System.FilePath.Posix      (takeDirectory)


-- | Templating error occurred during encryption.
data EncryptSystemError
  = EncryptFSError FSError                             -- ^ 'FSError' occurred during encryption.
  | EncryptTemplateError Template.EncryptTemplateError -- ^ Internal 'Template.EncryptTemplateError'.
    deriving (Eq, Show)

-- | Templating error occurred during decryption.
data DecryptSystemError
  = DecryptFSError FSError                             -- ^ 'FSError' occurred during decryption.
  | DecryptTemplateError Template.DecryptTemplateError -- ^ Internal 'Template.DecryptTemplateError'.
    deriving (Eq, Show)

-- | File system related error.
data FSError
  = InputFileNotFound       -- ^ Input file doesn't exist.
  | OutputDirectoryNotFound -- ^ Directory where output should be generated at doesn't exist.
    deriving (Eq, Show)

-- | For a given template update all the plain-text holes with encrypted values and produce a file in a given filepath.
encrypt :: FilePath -- ^ Input file.
        -> FilePath -- ^ Output file.
        -> IO (Maybe EncryptSystemError)
encrypt input output =
  fmap (either Just (const Nothing)) . runExceptT $ do
    liftIO (doesFileExist input) >>=
      throwUnless (EncryptFSError InputFileNotFound)
    liftIO (doesDirectoryExist (takeDirectory input)) >>=
      throwUnless (EncryptFSError OutputDirectoryNotFound)
    g :: CtrDRBG <- liftIO newGenIO
    liftIO (TLIO.readFile input >>= fmap fst . flip Template.encrypt g) >>=
      either (throwE . EncryptTemplateError) (liftIO . TLIO.writeFile output)

-- | For a given template update all the encrypted-text holes with decrypted values and produce a file in a given filepath.
decrypt :: FilePath -- ^ Input file.
        -> FilePath -- ^ Output file.
        -> IO (Maybe DecryptSystemError)
decrypt input output = do
  fmap (either Just (const Nothing)) . runExceptT $ do
    liftIO (doesFileExist input) >>=
      throwUnless (DecryptFSError InputFileNotFound)
    liftIO (doesDirectoryExist (takeDirectory input)) >>=
      throwUnless (DecryptFSError OutputDirectoryNotFound)
    liftIO (TLIO.readFile input >>= Template.decrypt) >>=
      either (throwE . DecryptTemplateError) (liftIO . TLIO.writeFile output)

throwUnless :: Monad m => e -> Bool -> ExceptT e m ()
throwUnless = flip unless . throwE
