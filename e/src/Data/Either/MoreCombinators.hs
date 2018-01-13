{-# LANGUAGE LambdaCase #-}
-- | @Data.Either.Combinators@ extended.
module Data.Either.MoreCombinators
  ( bimapExceptT
  , mapLeftT
  , left
  , right
  , note
  , hoistEither
  , module Data.Either.Combinators
  ) where

import Control.Monad.Trans.Except
import Data.Either.Combinators

-- | Analogous to 'Left'.
left :: Monad m => e -> ExceptT e m a
left = ExceptT . return . Left
{-# INLINE left #-}

-- | Analogous to 'Right'.
right :: Monad m => a -> ExceptT e m a
right = return
{-# INLINE right #-}

-- | Tag the 'Nothing' value of a 'Maybe'.
note :: b -> Maybe a -> Either b a
note x =
  \case
    Nothing -> Left x
    Just y -> Right y
{-# INLINE note #-}

-- | Map over both failure and success.
bimapExceptT :: Functor m => (e -> f) -> (a -> b) -> ExceptT e m a -> ExceptT f m b
bimapExceptT f g (ExceptT m) = ExceptT (fmap h m) where
  h (Left e)  = Left (f e)
  h (Right a) = Right (g a)
{-# INLINE bimapExceptT #-}

-- | Alias for `bimapEitherT f id`.
mapLeftT :: Functor m => (a -> b) -> ExceptT a m c -> ExceptT b m c
mapLeftT f = bimapExceptT f id
{-# INLINE mapLeftT #-}

-- | Lift an 'Either' into an 'ExceptT'
hoistEither :: Monad m => Either e a -> ExceptT e m a
hoistEither = ExceptT . return
{-# INLINE hoistEither #-}
