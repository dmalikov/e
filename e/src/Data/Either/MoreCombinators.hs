{-# LANGUAGE LambdaCase #-}
-- | @Data.Either.Combinators@ extended.
module Data.Either.MoreCombinators
  ( note
  , mapLeftT
  ) where

import Control.Monad.Trans.Either

-- | Tag the 'Nothing' value of a 'Maybe'.
note :: b -> Maybe a -> Either b a
note x =
  \case
    Nothing -> Left x
    Just y -> Right y

-- | Alias for `bimapEitherT f id`.
mapLeftT :: Functor m => (a -> b) -> EitherT a m c -> EitherT b m c
mapLeftT f = bimapEitherT f id
