{-# Language InstanceSigs #-}
{-# Language LambdaCase #-}
-- | Cipher/decipher on the filesystem.
module E.Action
  (
  -- ** Action
  Action(..), act,
  -- ** Action arguments
  InFP(..), InMetaFP(..), Out(..), OutMetaFP(..),
  -- ** Error during Action
  ActError(..),
  -- * Action result
  ActResult(..)
  ) where

import Control.Monad (unless)
import Control.Monad.Except
import Control.Monad.Trans.Either
import Data.Aeson (eitherDecode)
import qualified Data.ByteString.Lazy as BSL
import Data.Either.Combinators
import Data.Either.MoreCombinators
import qualified Data.Text.IO as TIO
import System.Directory (doesFileExist)
import Data.Attoparsec.Text

import E.Encrypt
import E.Metadata
import E.Template

-- | Action on the filesystem.
data Action
  = ActEnc Algs InFP (Maybe InMetaFP) Out OutMetaFP
  | ActDec Algs InFP InMetaFP Out

-- | Input filepath.
newtype InFP = InFP { unInFP :: FilePath }
  deriving (Eq,Show)

-- | Output.
data Out
  = OutFP FilePath -- ^ Output filepath.
  | OutStd -- ^ Stdout.

-- | Input metadata filepath.
newtype InMetaFP = InMetaFP { unInMetaFP :: FilePath }
  deriving (Eq,Show)

-- | Output metadata filepath.
newtype OutMetaFP = OutMetaFP { unOutMetaFP :: FilePath }

-- | Possible error during 'Action'.
data ActError
  = InputFileNotFound InFP
  | InputMetadataFileNotFound InMetaFP
  | MetadataParsingError String
  | EncryptionError EError
  | DecryptionError EError
    deriving (Eq,Show)

-- | Result of an 'Action'.
data ActResult a = ActResult { runActResult :: EitherT ActError IO a }

instance Functor ActResult where
  fmap f (ActResult v) = ActResult (fmap f v)
  {-# INLINE fmap #-}

instance Applicative ActResult where
  pure = ActResult . right
  {-# INLINE pure #-}
  ActResult f <*> ActResult v = ActResult (f <*> v)
  {-# INLINE (<*>) #-}

-- | Multiple 'ActResult's could be chained.
instance Monad ActResult where
  m >>= f = ActResult . EitherT $ do
    a <- runEitherT (runActResult m)
    case a of
      Left l -> pure (Left l)
      Right r -> runEitherT (runActResult (f r))
  {-# INLINE (>>=) #-}
  return = pure
  {-# INLINE return #-}

instance MonadIO ActResult where
  liftIO = ActResult . lift

-- | Lift a computation from 'IO (Either ActError a)'.
liftIOEither :: IO (Either ActError a) -> ActResult a
liftIOEither = ActResult . EitherT

-- | Signal an exception 'ActError'.
actError :: ActError -> ActResult a
actError = ActResult . left

-- | Do 'encryptTem' reading input from the filesystem.
enc :: Algs -> Maybe InMetaFP -> InFP -> ActResult (Tem, Metadata)
enc e mimfp ifp = do
  m <- parseMetadataOrCreate mimfp
  t <- parseTemplate ifp
  ActResult (mapLeftT EncryptionError (encryptTem e m t))

-- | Do 'decryptTem' reading input from the filesystem.
dec :: Algs -> InMetaFP -> InFP -> ActResult Tem
dec e imfp ifp = do
  m <- parseMetadata imfp
  t <- parseTemplate ifp
  ActResult (mapLeftT DecryptionError (decryptTem e m t))

-- | Read 'Metadata' from a given 'Maybe InMetaFP'.
-- |
-- | Return 'empty' if file not found, throw 'InputMetadataFileNotFound' if it should be there.
parseMetadataOrCreate :: Maybe InMetaFP -> ActResult Metadata
parseMetadataOrCreate Nothing    = pure mempty
parseMetadataOrCreate (Just mfp) = parseMetadata mfp

-- | Read 'Metadata' from a given 'InMetaFP'.
-- |
-- | Throw 'InputFileNotFound' if file not found.
parseMetadata :: InMetaFP -> ActResult Metadata
parseMetadata mfp = do
  mfpe <- liftIO . doesFileExist . unInMetaFP $ mfp
  unless mfpe $ actError $ InputMetadataFileNotFound mfp
  liftIOEither
    (mapLeft MetadataParsingError  . eitherDecode <$> BSL.readFile (unInMetaFP mfp))

-- | Read 'Tem' from a given 'InFP'.
-- |
-- | Throw 'InputFileNotFound' if file not found.
parseTemplate :: InFP -> ActResult Tem
parseTemplate ifp = do
  ifpe <- liftIO . doesFileExist . unInFP $ ifp
  unless ifpe $ actError $ InputFileNotFound ifp
  liftIOEither
    (mapLeft absurd . parseOnly parseTem <$> TIO.readFile (unInFP ifp))
 where
  absurd _ = error "It cannot be! parseTemplate always returns Just Tem"

-- | Perform an 'Action'.
act :: Action -> ActResult ()
act (ActEnc e ifp mimfp out omfp) = do
  (t, m) <- enc e mimfp ifp
  liftIO $ do
    case out of
      OutFP ofp -> TIO.writeFile ofp (encode t)
      OutStd -> TIO.putStrLn (encode t)
    TIO.writeFile (unOutMetaFP omfp) (encode m)
act (ActDec e ifp imfp out) = do
  t <- dec e imfp ifp
  liftIO $
    case out of
      OutFP ofp -> TIO.writeFile ofp (encode t)
      OutStd -> TIO.putStrLn (encode t)
