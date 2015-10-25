{-# LANGUAGE LambdaCase #-}
-- | 'FilePath' templating mechanism with a power of 'Data.Text.Template.Encrypt'.
module System.Template.Encrypt
  ( encrypt
  , decrypt
  , EncryptSystemError(..)
  , DecryptSystemError(..)
  , FSError(..)
  ) where

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
  doesFileExist input >>= \case
    False -> return (Just (EncryptFSError InputFileNotFound))
    True  ->
      doesDirectoryExist (takeDirectory input) >>= \case
        False -> return (Just (EncryptFSError OutputDirectoryNotFound))
        True  ->
          TLIO.readFile input >>= Template.encrypt >>= \case
            Left e          -> return (Just (EncryptTemplateError e))
            Right encrypted -> TLIO.writeFile output encrypted >> return Nothing

-- | For a given template update all the encrypted-text holes with decrypted values and produce a file in a given filepath.
decrypt :: FilePath -- ^ Input file.
        -> FilePath -- ^ Output file.
        -> IO (Maybe DecryptSystemError)
decrypt input output = do
  doesFileExist input >>= \case
    False -> return (Just (DecryptFSError InputFileNotFound))
    True  -> do
      doesDirectoryExist (takeDirectory input) >>= \case
        False -> return (Just (DecryptFSError OutputDirectoryNotFound))
        True  -> do
          inputContent <- TLIO.readFile input
          eitherDecrypted <- Template.decrypt inputContent
          case eitherDecrypted of
            Left e          -> return (Just (DecryptTemplateError e))
            Right decrypted -> TLIO.writeFile output decrypted >> return Nothing
