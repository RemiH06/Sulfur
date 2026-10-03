{-# LANGUAGE CPP #-}

module Main (main) where

import Control.Exception (finally)
import Control.Monad (unless, when)
import Data.List (sortOn)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.IO qualified as TIO
import Sulfur.Fingerprint
import Sulfur.Vault
import System.Console.Haskeline
import System.Directory (XdgDirectory (XdgData), doesFileExist, getXdgDirectory)
import System.Environment (getArgs, lookupEnv)
import System.Exit (die)
import System.FilePath ((</>))
import System.IO
import Text.Printf (printf)
#if defined(mingw32_HOST_OS)
import System.Win32.Console (getConsoleOutputCP, setConsoleOutputCP)
#endif

main :: IO ()
main = withUtf8Console $ do
  mapM_ (`hSetEncoding` utf8) [stdout, stderr]
  args <- getArgs
  case args of
    ["color", text] -> cmdColor (T.pack text)
    ["init"] -> cmdInit
    ["add", name] -> cmdAdd (T.pack name)
    ["get", name] -> cmdGet (T.pack name)
    ["list"] -> cmdList
    _ ->
      die . unlines $
        [ "Uso:"
        , "  sulfur color \"<texto>\"   huella visual de un texto"
        , "  sulfur init              crea la bóveda"
        , "  sulfur add \"<nombre>\"    agrega una entrada"
        , "  sulfur get \"<nombre>\"    muestra el secreto de una entrada"
        , "  sulfur list              lista las entradas con su huella"
        ]

-- | La consola de Windows usa por default una página de códigos de 8 bits
-- (850 en español), que rompe acentos y cualquier Unicode. Se cambia a UTF-8
-- solo mientras corre sulfur y se restaura al salir, también si sale con error.
withUtf8Console :: IO a -> IO a
#if defined(mingw32_HOST_OS)
withUtf8Console action = do
  previous <- getConsoleOutputCP
  setConsoleOutputCP 65001
  action `finally` setConsoleOutputCP previous
#else
withUtf8Console = id
#endif

cmdColor :: Text -> IO ()
cmdColor text = do
  tty <- hIsTerminalDevice stdout
  let color = fingerprint text
  printf "%s%s  oklch(%.3f %.3f %.1f)\n" (swatch tty color) (toHex color)
    (lightness color) (chroma color) (hue color)

cmdInit :: IO ()
cmdInit = do
  path <- vaultPath
  exists <- doesFileExist path
  when exists $ die ("Ya existe una bóveda en " <> path)
  password <- askNew "Contraseña maestra nueva: " "Repítela: "
  when (T.length password < 12) $ die "La contraseña maestra debe tener al menos 12 caracteres."
  (v, _) <- newVault defaultKdf password >>= orDie
  saveVault path v
  putStrLn ("Bóveda creada en " <> path)

cmdAdd :: Text -> IO ()
cmdAdd name = do
  when (T.null (T.strip name)) $ die "El nombre no puede estar vacío."
  (path, v, key) <- openVault
  secret <- askNew "Secreto: " "Repítelo: "
  v' <- addEntry key (Entry name secret) v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  putStrLn (entryLine tty name)

-- | Solo escribe a una terminal: redirigido, el secreto acabaría en un
-- archivo o en otro proceso.
cmdGet :: Text -> IO ()
cmdGet name = do
  tty <- hIsTerminalDevice stdout
  unless tty $ die "get solo escribe en una terminal, nunca a un archivo o pipe."
  (_, v, key) <- openVault
  found <- orDie (findEntry key name v)
  maybe (die "No hay ninguna entrada con ese nombre.") (TIO.putStrLn . entrySecret) found

cmdList :: IO ()
cmdList = do
  (_, v, key) <- openVault
  es <- orDie (entries key v)
  tty <- hIsTerminalDevice stdout
  when (null es) $ putStrLn "La bóveda está vacía."
  mapM_ (putStrLn . entryLine tty . entryName) (sortOn entryName es)

-- | SULFUR_VAULT permite apuntar a otra bóveda; por default vive en el
-- directorio de datos del usuario (%APPDATA%\sulfur en Windows).
vaultPath :: IO FilePath
vaultPath = lookupEnv "SULFUR_VAULT" >>= maybe defaultPath pure
  where
    defaultPath = (</> "vault.json") <$> getXdgDirectory XdgData "sulfur"

openVault :: IO (FilePath, Vault, MasterKey)
openVault = do
  path <- vaultPath
  exists <- doesFileExist path
  unless exists $ die ("No hay bóveda en " <> path <> ". Créala con: sulfur init")
  v <- loadVault path >>= orDie
  password <- askSecret "Contraseña maestra: "
  key <- orDie (unlock password v)
  pure (path, v, key)

-- | Sin historial ni autocompletado: nada de lo que se teclea aquí se escribe
-- a disco.
askSecret :: String -> IO Text
askSecret label = do
  answer <- runInputT settings (getPassword Nothing label)
  maybe (die "Entrada cancelada.") (pure . T.pack) answer
  where
    settings = Settings {complete = noCompletion, historyFile = Nothing, autoAddHistory = False}

askNew :: String -> String -> IO Text
askNew label confirmLabel = do
  first <- askSecret label
  when (T.null first) $ die "No puede estar vacío."
  second <- askSecret confirmLabel
  unless (first == second) $ die "No coinciden."
  pure first

orDie :: Either VaultError a -> IO a
orDie = either (die . describe) pure

describe :: VaultError -> String
describe err = case err of
  WrongPassword -> "Contraseña maestra incorrecta."
  TamperedEntry -> "Una entrada no pasó la verificación: el archivo fue alterado o está dañado."
  CorruptEntry -> "Una entrada se descifró pero su contenido no es válido."
  DuplicateName n -> "Ya existe una entrada llamada " <> T.unpack n <> "."
  InvalidFile e -> "El archivo de la bóveda no es válido: " <> e
  InvalidKdfParams -> "Parámetros de Argon2 inválidos."

entryLine :: Bool -> Text -> String
entryLine tty name = swatch tty color <> toHex color <> "  " <> T.unpack name
  where
    color = fingerprint name

-- | Muestra de color en terminales con truecolor; se omite al redirigir.
swatch :: Bool -> Oklch -> String
swatch False _ = ""
swatch True color = printf "\ESC[48;2;%d;%d;%dm    \ESC[0m " r g b
  where
    (r, g, b) = toSrgb color
