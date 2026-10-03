{-# LANGUAGE CPP #-}

module Main (main) where

import Control.Exception (finally)
import Control.Monad (unless, when)
import Data.List (dropWhileEnd, sortOn)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.IO qualified as TIO
import Sulfur.Fingerprint
import Sulfur.Password (generatePassword)
import Sulfur.Vault
import System.Console.Haskeline
import System.Directory (XdgDirectory (XdgData), doesFileExist, getXdgDirectory)
import System.Environment (getArgs, lookupEnv)
import System.Exit (die)
import System.FilePath ((</>))
import System.IO
import Text.Printf (printf)
import Text.Read (readMaybe)
#if defined(mingw32_HOST_OS)
import System.Win32.Console (getConsoleOutputCP, setConsoleOutputCP)
#endif

main :: IO ()
main = withUtf8Console $ do
  mapM_ (`hSetEncoding` utf8) [stdin, stdout, stderr]
  args <- getArgs
  case args of
    ["color", text] -> cmdColor (T.pack text)
    ["init"] -> cmdInit
    ["add", name] -> cmdAdd (T.pack name)
    ["get", name] -> cmdGet (T.pack name)
    ["list"] -> cmdList
    ["gen", name] -> cmdGen (T.pack name) defaultLength
    ["gen", name, len] -> maybe usage (cmdGen (T.pack name)) (readMaybe len)
    ["edit", name] -> cmdEdit (T.pack name)
    ["rm", name] -> cmdRemove (T.pack name)
    ["mv", old, new] -> cmdRename (T.pack old) (T.pack new)
    ["passwd"] -> cmdPasswd
    _ -> usage

usage :: IO a
usage =
  die . unlines $
    [ "Uso:"
    , "  sulfur color \"<texto>\"             huella visual de un texto"
    , "  sulfur init                        crea la bóveda"
    , "  sulfur add \"<nombre>\"              agrega una entrada con un secreto tecleado"
    , "  sulfur gen \"<nombre>\" [longitud]   genera el secreto (default " <> show defaultLength <> "); si existe, lo reemplaza"
    , "  sulfur get \"<nombre>\"              muestra el secreto de una entrada"
    , "  sulfur edit \"<nombre>\"             cambia el secreto por uno tecleado"
    , "  sulfur rm \"<nombre>\"               borra una entrada"
    , "  sulfur mv \"<nombre>\" \"<nuevo>\"     renombra una entrada (su huella cambia)"
    , "  sulfur list                        lista las entradas con su huella"
    , "  sulfur passwd                      cambia la contraseña maestra"
    ]

defaultLength :: Int
defaultLength = 24

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
  password <- askNewMaster
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
  e <- orDie (lookupEntry key name v)
  TIO.putStrLn (entrySecret e)

-- | No muestra el secreto generado; para verlo, `get`.
cmdGen :: Text -> Int -> IO ()
cmdGen name len = do
  when (T.null (T.strip name)) $ die "El nombre no puede estar vacío."
  when (len < 12 || len > 128) $ die "La longitud debe estar entre 12 y 128."
  (path, v, key) <- openVault
  secret <- generatePassword len
  v' <- case lookupEntry key name v of
    Left (EntryNotFound _) -> addEntry key (Entry name secret) v >>= orDie
    Left err -> die (describe err)
    Right _ -> do
      ok <- confirm (T.unpack name <> " ya existe. ¿Reemplazar su secreto por uno generado? [s/N] ")
      unless ok $ die "Sin cambios."
      replaceSecret key name secret v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  putStrLn (entryLine tty name)

cmdEdit :: Text -> IO ()
cmdEdit name = do
  (path, v, key) <- openVault
  _ <- orDie (lookupEntry key name v)
  secret <- askNew "Secreto nuevo: " "Repítelo: "
  v' <- replaceSecret key name secret v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  putStrLn (entryLine tty name)

cmdRemove :: Text -> IO ()
cmdRemove name = do
  (path, v, key) <- openVault
  v' <- removeEntry key name v >>= orDie
  ok <- confirm ("¿Borrar " <> T.unpack name <> "? No se puede deshacer. [s/N] ")
  unless ok $ die "Sin cambios."
  saveVault path v'
  putStrLn ("Borrada: " <> T.unpack name)

-- | Muestra la huella anterior y la nueva: al cambiar el nombre cambia el color.
cmdRename :: Text -> Text -> IO ()
cmdRename old new = do
  when (T.null (T.strip new)) $ die "El nombre no puede estar vacío."
  (path, v, key) <- openVault
  v' <- renameEntry key old new v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  putStrLn (entryLine tty old)
  putStrLn (entryLine tty new)

-- | Sal, verificación y parámetros de Argon2 nuevos; todas las entradas se
-- vuelven a sellar.
cmdPasswd :: IO ()
cmdPasswd = do
  (path, v, key) <- openVault
  password <- askNewMaster
  (v', _) <- changeMaster key defaultKdf password v >>= orDie
  saveVault path v'
  putStrLn "Contraseña maestra cambiada."

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

-- | Lee una línea. En una consola real usa haskeline, que lee Unicode con la
-- API de Windows y puede ocultar lo tecleado; sin historial ni autocompletado,
-- así que nada se escribe a disco. Si la entrada no es una consola (pipe,
-- Git Bash), haskeline decodificaría con la página de códigos del sistema y
-- una maestra con "ñ" daría otra clave, así que ahí se lee directo como UTF-8.
readInput :: Bool -> String -> IO (Maybe String)
readInput hidden label = do
  console <- hIsTerminalDevice stdin
  if console
    then runInputT quiet ((if hidden then getPassword Nothing else getInputLine) label)
    else do
      putStr label >> hFlush stdout
      eof <- hIsEOF stdin
      if eof then pure Nothing else Just . dropWhileEnd (== '\r') <$> hGetLine stdin
  where
    quiet = Settings {complete = noCompletion, historyFile = Nothing, autoAddHistory = False}

askSecret :: String -> IO Text
askSecret label = readInput True label >>= maybe (die "Entrada cancelada.") (pure . T.pack)

askNew :: String -> String -> IO Text
askNew label confirmLabel = do
  first <- askSecret label
  when (T.null first) $ die "No puede estar vacío."
  second <- askSecret confirmLabel
  unless (first == second) $ die "No coinciden."
  pure first

askNewMaster :: IO Text
askNewMaster = do
  password <- askNew "Contraseña maestra nueva: " "Repítela: "
  when (T.length password < 12) $ die "La contraseña maestra debe tener al menos 12 caracteres."
  pure password

confirm :: String -> IO Bool
confirm question = do
  answer <- readInput False question
  pure (maybe False ((`elem` ["s", "si", "sí"]) . T.unpack . T.toLower . T.strip . T.pack) answer)

orDie :: Either VaultError a -> IO a
orDie = either (die . describe) pure

describe :: VaultError -> String
describe err = case err of
  WrongPassword -> "Contraseña maestra incorrecta."
  TamperedEntry -> "Una entrada no pasó la verificación: el archivo fue alterado o está dañado."
  TamperedIndex -> "La lista de entradas no coincide con el índice: se borraron, reordenaron o reemplazaron entradas."
  CorruptEntry -> "Una entrada se descifró pero su contenido no es válido."
  DuplicateName n -> "Ya existe una entrada llamada " <> T.unpack n <> "."
  EntryNotFound n -> "No hay ninguna entrada llamada " <> T.unpack n <> "."
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
