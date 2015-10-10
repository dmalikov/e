{-# LANGUAGE LambdaCase #-}
-- | 'FilePath' templating mechanism with a power of 'Data.Text.Encrypt.Template'. TODO: probably it's a System.FilePath.Encrypt.Template?
module Data.Text.Encrypt.Template.IO
  ( encrypt
  , decrypt
  , EncryptTemplateIOError(..)
  , DecryptTemplateIOError(..)
  ) where

import qualified Data.Text.Encrypt.Template as Template
import qualified Data.Text.Lazy.IO          as TLIO
import           System.Directory           (doesDirectoryExist, doesFileExist)
import           System.FilePath.Posix      (takeDirectory)
import           System.IO                  (IOMode (..), hClose, openFile)

-- | Templating error occurred during encryption.
data EncryptTemplateIOError -- TODO: maybe it's a EncryptSystemError?
  = EncryptInputFileDoesntExist                        -- ^ Input file doesn't exist.
  | EncryptOutputDirectoryDoesntExist                  -- ^ Directory where output should be generated at doesn't exist.
  | EncryptTemplateError Template.EncryptTemplateError -- ^ Internal 'Template.EncryptTemplateError'.
    deriving (Eq, Show)

-- | Templating error occurred during decryption.
data DecryptTemplateIOError
  = DecryptInputFileDoesntExist                        -- ^ Input file doesn't exist. TODO: looks kinda familiar.
  | DecryptOutputDirectoryDoesntExist                  -- ^ Directory where output should be generated at doesn't exist. TODO: again ((
  | DecryptTemplateError Template.DecryptTemplateError -- ^ Internal 'Template.DecryptTemplateError'.
    deriving (Eq, Show)

-- | For a given template update all the plain-text holes with encrypted values and produce a file in a given filepath.
encrypt :: FilePath -- ^ Input file.
        -> FilePath -- ^ Output file.
        -> IO (Maybe EncryptTemplateIOError)
encrypt input output = do
  doesFileExist input >>= \case
    False -> return (Just EncryptInputFileDoesntExist)
    True  -> do
      doesDirectoryExist (takeDirectory input) >>= \case
        False -> return (Just EncryptOutputDirectoryDoesntExist)
        True  -> do
          handleIn  <- openFile input ReadMode
          handleOut <- openFile output WriteMode
          inputContent <- TLIO.hGetContents handleIn
          eitherEncrypted <- Template.encrypt inputContent
          hClose handleIn
          case eitherEncrypted of
            Left e          -> do
              hClose handleOut
              return (Just (EncryptTemplateError e))
            Right encrypted -> do
              TLIO.hPutStr handleOut encrypted
              hClose handleOut
              return Nothing

-- | For a given template update all the encrypted-text holes with decrypted values and produce a file in a given filepath.
decrypt :: FilePath -- ^ Input file.
        -> FilePath -- ^ Output file.
        -> IO (Maybe DecryptTemplateIOError)
decrypt input output = do
  doesFileExist input >>= \case
    False -> return (Just DecryptInputFileDoesntExist)
    True  -> do
      doesDirectoryExist (takeDirectory input) >>= \case
        False -> return (Just DecryptOutputDirectoryDoesntExist)
        True  -> do
          handleIn  <- openFile input ReadMode
          handleOut <- openFile output WriteMode
          inputContent <- TLIO.hGetContents handleIn
          eitherDecrypted <- Template.decrypt inputContent
          hClose handleIn
          case eitherDecrypted of
            Left e          -> do
              hClose handleOut
              return (Just (DecryptTemplateError e))
            Right decrypted -> do
              TLIO.hPutStr handleOut decrypted
              hClose handleOut
              return Nothing
