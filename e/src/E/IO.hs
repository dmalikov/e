-- | 'E' support for 'IO'
module E.IO (decIO) where

import Control.Monad.Trans.Either
import Control.Exception.Base

import E

-- | Decrypt and throw an error if failed.
decIO :: Algs     -- ^ Algorithms
      -> FilePath -- ^ Input file.
      -> FilePath -- ^ Input 'Metadata' file.
      -> FilePath -- ^ Output file.
      -> IO ()
decIO args f m o = do
  result <- runEitherT $ runActResult $ act $ ActDec args (InFP f) (InMetaFP m) (OutFP o)
  case result of
    Left e  -> throw $ userError $ show e
    Right _ -> return ()
