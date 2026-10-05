-- | Encontrar entradas sin teclear el nombre exacto.
module Sulfur.Search
  ( matchEntries
  , fold
  ) where

import Data.Char (isMark)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Normalize (NormalizationMode (NFC, NFD), normalize)
import Sulfur.Vault (Entry (..))

-- | Tres niveles, del más estricto al más laxo; gana el primero que encuentre
-- algo: nombre exacto (en NFC), nombre igual sin mayúsculas ni acentos, y
-- nombre que contiene lo buscado. Así `git` da "git" aunque exista "github",
-- y `gmail` da "Gmail personal" y "Gmail trabajo" para elegir.
matchEntries :: Text -> [Entry] -> [Entry]
matchEntries query es = case filter (not . null) tiers of
  (found : _) -> found
  [] -> []
  where
    q = fold query
    tiers =
      [ [e | e <- es, entryName e == normalize NFC query]
      , [e | e <- es, fold (entryName e) == q]
      , [e | e <- es, not (T.null q), q `T.isInfixOf` fold (entryName e)]
      ]

-- | Minúsculas sin acentos: NFD separa las letras de sus marcas y se quitan
-- las marcas.
fold :: Text -> Text
fold = T.toCaseFold . T.filter (not . isMark) . normalize NFD . T.strip
