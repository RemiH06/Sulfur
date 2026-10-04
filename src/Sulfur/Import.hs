-- | Lectura de un archivo `nombre=secreto` para cargar muchas entradas de una
-- vez. El archivo tiene los secretos en claro: los errores nunca los repiten,
-- solo dan número de línea y nombre.
module Sulfur.Import
  ( parseEntries
  ) where

import Data.Either (lefts, rights)
import Data.List (mapAccumL)
import Data.Maybe (catMaybes)
import Data.Text (Text)
import Data.Text qualified as T
import Sulfur.Vault (Entry (..))

-- | Categoría y usuario que aplican a las entradas de abajo.
type Group = (Maybe Text, Maybe Text)

-- | Una entrada por línea, `nombre=secreto`, partida en el primer `=`: el
-- nombre puede llevar espacios y el secreto puede llevar `=` o `#`. El secreto
-- se toma literal, sin recortar espacios. Una línea `[categoría | usuario]`
-- (o `[categoría]`, o `[| usuario]`) aplica a las entradas de abajo hasta el
-- siguiente encabezado; `[]` vuelve a nada. Se ignoran líneas vacías, las que
-- empiezan con `#`, el BOM que agrega el Bloc de notas y el `\r` de los
-- finales CRLF. Un secreto entre comillas se rechaza en vez de adivinar si las
-- comillas son parte de la contraseña.
parseEntries :: Text -> Either [String] [Entry]
parseEntries content = case lefts results of
  [] -> Right (rights results)
  errs -> Left errs
  where
    numbered = zip [1 :: Int ..] (map (T.dropWhileEnd (== '\r')) (T.lines (T.dropWhile (== '\xfeff') content)))
    results = catMaybes (snd (mapAccumL step (Nothing, Nothing) numbered))
    step group (n, line)
      | T.null stripped || T.pack "#" `T.isPrefixOf` stripped = (group, Nothing)
      | isHeader stripped = (parseHeader stripped, Nothing)
      | otherwise = (group, Just (parseLine group n line))
      where
        stripped = T.strip line

-- | Entre corchetes y sin `=`, para que una entrada como `[x=y]` no se lea
-- como encabezado.
isHeader :: Text -> Bool
isHeader s = T.pack "[" `T.isPrefixOf` s && T.pack "]" `T.isSuffixOf` s && not (T.any (== '=') s)

parseHeader :: Text -> Group
parseHeader s = (nonEmpty category, nonEmpty (T.drop 1 rest))
  where
    (category, rest) = T.breakOn (T.pack "|") (T.drop 1 (T.dropEnd 1 s))
    nonEmpty t = let t' = T.strip t in if T.null t' then Nothing else Just t'

parseLine :: Group -> Int -> Text -> Either String Entry
parseLine (category, login) n line
  | T.null rest = Left (at "falta el signo =")
  | T.null name = Left (at "falta el nombre antes del =")
  | T.null secret = Left (at ("el secreto de " <> T.unpack name <> " está vacío"))
  | quoted = Left (at ("el secreto de " <> T.unpack name <> " está entre comillas; quítalas si no son parte de la contraseña"))
  | otherwise = Right (Entry name secret login category)
  where
    (rawName, rest) = T.breakOn (T.pack "=") line
    name = T.strip rawName
    secret = T.drop 1 rest
    quoted = T.length secret >= 2 && T.head secret `elem` ['"', '\''] && T.head secret == T.last secret
    at msg = "línea " <> show n <> ": " <> msg
