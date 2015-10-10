module Data.Text.Encrypt.Template.IOSpec
  ( main, spec
  ) where

import qualified Data.Text.Encrypt.Template.IO as TETIO
import qualified Data.Text.Lazy.IO             as TLIO
import           Paths_e
import           System.Environment            (setEnv)
import           System.FilePath               (takeDirectory, (</>))
import           Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "encrypt templating files" $ do
    it "decrypts encrypted file" $ do
      encryptedFilePath <- getDataFileName "test/data/encrypted"
      plainFilePath     <- getDataFileName "test/data/plain"
      let testDataFilePath = takeDirectory encryptedFilePath
      let decryptedFilePath = testDataFilePath </> "decrypted"
      setEnv "E_KEYS_STORE" (testDataFilePath </> "keys")
      TETIO.decrypt encryptedFilePath decryptedFilePath `shouldReturn` Nothing
      expected <- TLIO.readFile plainFilePath
      actual   <- TLIO.readFile decryptedFilePath
      actual `shouldBe` expected

