-- | Lectura de un archivo `nombre=secreto` para cargar muchas entradas de una
-- vez. El archivo tiene los secretos en claro: los errores nunca los repiten,
-- solo dan número de línea y nombre.
module Sulfur.Import
  ( parseEntries
  ) where

import Data.Text (Text)
import Data.Text qualified as T
import Sulfur.Vault (Entry (..))

-- | Una entrada por línea, `nombre=secreto`, partida en el primer `=`: el
-- nombre puede llevar espacios y el secreto puede llevar `=`. El secreto se
-- toma literal, sin recortar espacios. Se ignoran líneas vacías, comentarios
-- con `#`, el BOM que agrega el Bloc de notas y el `\r` de los finales CRLF.
-- Un secreto entre comillas se rechaza en vez de adivinar si las comillas son
-- parte de la contraseña.
parseEntries :: Text -> Either [String] [Entry]
parseEntries content = case [err | Left err <- parsed] of
  [] -> Right [e | Right e <- parsed]
  errs -> Left errs
  where
    parsed =
      [ parseLine n line
      | (n, line) <- zip [1 :: Int ..] (map (T.dropWhileEnd (== '\r')) (T.lines (T.dropWhile (== '\xfeff') content)))
      , not (T.null (T.strip line))
      , not (T.pack "#" `T.isPrefixOf` T.stripStart line)
      ]

parseLine :: Int -> Text -> Either String Entry
parseLine n line
  | T.null rest = Left (at "falta el signo =")
  | T.null name = Left (at "falta el nombre antes del =")
  | T.null secret = Left (at ("el secreto de " <> T.unpack name <> " está vacío"))
  | quoted = Left (at ("el secreto de " <> T.unpack name <> " está entre comillas; quítalas si no son parte de la contraseña"))
  | otherwise = Right (Entry name secret)
  where
    (rawName, rest) = T.breakOn (T.pack "=") line
    name = T.strip rawName
    secret = T.drop 1 rest
    quoted = T.length secret >= 2 && T.head secret `elem` ['"', '\''] && T.head secret == T.last secret
    at msg = "línea " <> show n <> ": " <> msg
