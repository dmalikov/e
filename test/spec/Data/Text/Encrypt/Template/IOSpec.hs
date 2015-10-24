module Data.Text.Encrypt.Template.IOSpec
  ( main, spec
  ) where

import qualified Data.Text.Lazy.IO       as TLIO
import           Paths_e
import           System.Environment      (setEnv)
import           System.FilePath         (takeDirectory, (</>))
import           System.Template.Encrypt (decrypt)
import           Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "encrypt templating files" $ do
    it "decrypts encrypted file" $ do
      encryptedFilePath <- getDataFileName "test/data/.netrc.encrypted"
      plainFilePath     <- getDataFileName "test/data/.netrc"
      let testDataFilePath = takeDirectory encryptedFilePath
      let decryptedFilePath = testDataFilePath </> ".netrc.decrypted"
      setEnv "E_KEYS_STORE" (testDataFilePath </> "keys")
      decrypt encryptedFilePath decryptedFilePath `shouldReturn` Nothing
      expected <- TLIO.readFile plainFilePath
      actual   <- TLIO.readFile decryptedFilePath
      actual `shouldBe` expected

