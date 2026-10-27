-- | Detecta que la bóveda cambió fuera de Sulfur, por ejemplo al regresarla
-- entera a una versión vieja, que el índice sellado no puede notar porque esa
-- versión es válida. Fuera de la bóveda se guarda el SHA-256 del archivo tal
-- como Sulfur lo dejó; si al abrir no coincide, alguien lo reemplazó.
--
-- Perder ese registro no bloquea nada: la bóveda se vuelve a aceptar como la
-- primera vez. Quien pueda borrar el registro y reemplazar la bóveda (el mismo
-- usuario de Windows) puede saltarse la detección; esto atrapa restauraciones
-- por error y copias reemplazadas en otro lado (respaldo, nube, USB).
module Sulfur.Rollback
  ( Seen (..)
  , checkSeen
  , recordSeen
  ) where

import Crypto.Hash (Digest, SHA256, hash)
import Data.ByteString (ByteString)
import Data.ByteString.Char8 qualified as BC
import Data.Text qualified as T
import Data.Text.Encoding (encodeUtf8)
import System.Directory (canonicalizePath, createDirectoryIfMissing, doesFileExist, renameFile)
import System.FilePath ((</>))

data Seen
  = -- | No hay registro de esta bóveda en este equipo.
    FirstTime
  | -- | El archivo es el que dejó Sulfur la última vez.
    Unchanged
  | -- | El archivo cambió sin pasar por Sulfur.
    ChangedOutside
  deriving (Eq, Show)

-- | Compara el contenido actual de la bóveda con el registrado en `stateDir`.
checkSeen :: FilePath -> FilePath -> ByteString -> IO Seen
checkSeen stateDir vault bytes = do
  file <- recordFile stateDir vault
  exists <- doesFileExist file
  if not exists
    then pure FirstTime
    else do
      recorded <- BC.strip <$> BC.readFile file
      pure (if recorded == digest bytes then Unchanged else ChangedOutside)

-- | Registra el contenido actual como el último que dejó Sulfur.
recordSeen :: FilePath -> FilePath -> ByteString -> IO ()
recordSeen stateDir vault bytes = do
  createDirectoryIfMissing True stateDir
  file <- recordFile stateDir vault
  let tmp = file <> ".tmp"
  BC.writeFile tmp (digest bytes)
  renameFile tmp file

-- | Un registro por bóveda, nombrado por el hash de su ruta completa.
recordFile :: FilePath -> FilePath -> IO FilePath
recordFile stateDir vault = do
  full <- canonicalizePath vault
  pure (stateDir </> BC.unpack (digest (encodeUtf8 (T.pack full))))

digest :: ByteString -> ByteString
digest = BC.pack . show . (hash :: ByteString -> Digest SHA256)
