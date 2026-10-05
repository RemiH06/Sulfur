{-# LANGUAGE CPP #-}

module Main (main) where

import Clipboard (copyTransient)
import Control.Exception (finally)
import Control.Monad (unless, when)
import Data.List (dropWhileEnd, sortOn)
import Data.Maybe (fromMaybe, isNothing)
import Data.Text (Text)
import Data.Text qualified as T
import Data.ByteString qualified as BS
import Data.Text.Encoding (decodeUtf8')
import Data.Text.IO qualified as TIO
import Sulfur.Fingerprint
import Sulfur.Import (parseEntries)
import Sulfur.Password (generatePassword)
import Sulfur.Search (matchEntries)
import Sulfur.Vault
import System.Console.Haskeline
import System.Directory (XdgDirectory (XdgData), doesFileExist, getXdgDirectory, removeFile)
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
    ["copy", name] -> cmdCopy (T.pack name)
    ["list"] -> cmdList Nothing
    ["list", category] -> cmdList (Just (T.pack category))
    ["set", name, field, value] -> cmdSet (T.pack name) field (T.pack value)
    ["gen", name] -> cmdGen (T.pack name) defaultLength
    ["gen", name, len] -> maybe usage (cmdGen (T.pack name)) (readMaybe len)
    ["edit", name] -> cmdEdit (T.pack name)
    ["rm", name] -> cmdRemove (T.pack name)
    ["mv", old, new] -> cmdRename (T.pack old) (T.pack new)
    ["passwd"] -> cmdPasswd
    ["import", file] -> cmdImport file
    _ -> usage

usage :: IO a
usage =
  die . unlines $
    [ "Uso:"
    , "  sulfur color \"<texto>\"             huella visual de un texto"
    , "  sulfur init                        crea la bóveda"
    , "  sulfur add \"<nombre>\"              agrega una entrada con un secreto tecleado"
    , "  sulfur gen \"<nombre>\" [longitud]   genera el secreto (default " <> show defaultLength <> "); si existe, lo reemplaza"
    , "  sulfur copy \"<nombre>\"             copia el secreto al portapapeles por " <> show clipboardSeconds <> " s, fuera del historial"
    , "  sulfur get \"<nombre>\"              muestra el secreto de una entrada"
    , "  sulfur edit \"<nombre>\"             cambia el secreto por uno tecleado"
    , "  sulfur rm \"<nombre>\"               borra una entrada"
    , "  sulfur mv \"<nombre>\" \"<nuevo>\"     renombra una entrada (su huella cambia)"
    , "  sulfur set \"<nombre>\" usuario \"<valor>\"     cambia el correo o usuario (\"\" lo borra)"
    , "  sulfur set \"<nombre>\" categoria \"<valor>\"   cambia la categoría (\"\" la borra)"
    , "  sulfur list [categoría]            lista las entradas con su huella, categoría y usuario"
    , "  sulfur passwd                      cambia la contraseña maestra"
    , "  sulfur import \"<archivo>\"          carga entradas nombre=secreto, una por línea"
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
  (login, category) <- askMeta
  v' <- addEntry key (Entry name secret login category) v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  putStrLn (entryLine tty name)

-- | Solo escribe a una terminal: redirigido, el secreto acabaría en un
-- archivo o en otro proceso.
cmdGet :: Text -> IO ()
cmdGet query = do
  tty <- hIsTerminalDevice stdout
  unless tty $ die "get solo escribe en una terminal, nunca a un archivo o pipe."
  (_, v, key) <- openVault
  e <- resolve key query v
  when (entryName e /= query) $ putStrLn (entryLine tty (entryName e))
  TIO.putStrLn (entrySecret e)

-- | El secreto no pasa por la pantalla ni por el historial de la terminal.
cmdCopy :: Text -> IO ()
cmdCopy query = do
  (_, v, key) <- openVault
  e <- resolve key query v
  putStrLn
    ( "Copiado " <> T.unpack (entryName e) <> " "
        <> maybe "" (\l -> "(usuario: " <> T.unpack l <> ") ") (entryLogin e)
        <> "Se borra en " <> show clipboardSeconds <> " s; Ctrl+C lo borra ya."
    )
  hFlush stdout
  cleared <- copyTransient clipboardSeconds (entrySecret e)
  putStrLn $
    if cleared
      then "Portapapeles vaciado."
      else "Copiaste otra cosa encima; no se tocó el portapapeles."

clipboardSeconds :: Int
clipboardSeconds = 30

-- | No muestra el secreto generado; para verlo, `get` o `copy`.
cmdGen :: Text -> Int -> IO ()
cmdGen name len = do
  when (T.null (T.strip name)) $ die "El nombre no puede estar vacío."
  when (len < 12 || len > 128) $ die "La longitud debe estar entre 12 y 128."
  (path, v, key) <- openVault
  secret <- generatePassword len
  v' <- case lookupEntry key name v of
    Left (EntryNotFound _) -> do
      (login, category) <- askMeta
      addEntry key (Entry name secret login category) v >>= orDie
    Left err -> die (describe err)
    Right _ -> do
      ok <- confirm (T.unpack name <> " ya existe. ¿Reemplazar su secreto por uno generado? [s/N] ")
      unless ok $ die "Sin cambios."
      replaceSecret key name secret v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  putStrLn (entryLine tty name)

cmdEdit :: Text -> IO ()
cmdEdit query = do
  (path, v, key) <- openVault
  name <- entryName <$> resolve key query v
  secret <- askNew ("Secreto nuevo para " <> T.unpack name <> ": ") "Repítelo: "
  v' <- replaceSecret key name secret v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  putStrLn (entryLine tty name)

cmdRemove :: Text -> IO ()
cmdRemove query = do
  (path, v, key) <- openVault
  name <- entryName <$> resolve key query v
  v' <- removeEntry key name v >>= orDie
  ok <- confirm ("¿Borrar " <> T.unpack name <> "? No se puede deshacer. [s/N] ")
  unless ok $ die "Sin cambios."
  saveVault path v'
  putStrLn ("Borrada: " <> T.unpack name)

cmdSet :: Text -> String -> Text -> IO ()
cmdSet query field value = do
  setter <- case field of
    _ | field `elem` ["usuario", "correo"] -> pure setLogin
    _ | field `elem` ["categoria", "categoría"] -> pure setCategory
    _ -> die "El campo debe ser usuario o categoria."
  (path, v, key) <- openVault
  name <- entryName <$> resolve key query v
  v' <- setter key name (Just value) v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  putStrLn (entryLine tty name)

-- | Muestra la huella anterior y la nueva: al cambiar el nombre cambia el color.
cmdRename :: Text -> Text -> IO ()
cmdRename query new = do
  when (T.null (T.strip new)) $ die "El nombre no puede estar vacío."
  (path, v, key) <- openVault
  old <- entryName <$> resolve key query v
  v' <- renameEntry key old new v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  putStrLn (entryLine tty old)
  putStrLn (entryLine tty new)

-- | Carga muchas entradas de un archivo `nombre=secreto`. El archivo se valida
-- completo antes de pedir la maestra, se importan todas o ninguna, y al final
-- ofrece borrarlo porque tiene los secretos en claro.
cmdImport :: FilePath -> IO ()
cmdImport file = do
  exists <- doesFileExist file
  unless exists $ die ("No existe " <> file)
  content <- either (const (die (file <> " no está en UTF-8."))) pure . decodeUtf8' =<< BS.readFile file
  new <- either (die . unlines . ("No se importó nada:" :)) pure (parseEntries content)
  when (null new) $ die ("No hay entradas en " <> file)
  (path, v, key) <- openVault
  v' <- addEntries key new v >>= orDie
  saveVault path v'
  tty <- hIsTerminalDevice stdout
  mapM_ (putStrLn . entryLine tty . entryName) new
  putStrLn ("Importadas: " <> show (length new))
  ok <- confirm ("¿Borrar " <> file <> "? Tiene los secretos en claro. [s/N] ")
  if ok
    then removeFile file >> putStrLn ("Borrado: " <> file)
    else putStrLn ("Quedó en disco: " <> file <> ". Bórralo cuando termines.")

-- | Sal, verificación y parámetros de Argon2 nuevos; todas las entradas se
-- vuelven a sellar.
cmdPasswd :: IO ()
cmdPasswd = do
  (path, v, key) <- openVault
  password <- askNewMaster
  (v', _) <- changeMaster key defaultKdf password v >>= orDie
  saveVault path v'
  putStrLn "Contraseña maestra cambiada."

-- | Agrupa por categoría (las que no tienen van al final) y alinea columnas.
cmdList :: Maybe Text -> IO ()
cmdList only = do
  (_, v, key) <- openVault
  es <- orDie (entries key v)
  tty <- hIsTerminalDevice stdout
  let shown = sortOn order (maybe id (filter . inCategory) only es)
      order e = (isNothing (entryCategory e), T.toCaseFold <$> entryCategory e, T.toCaseFold (entryName e))
      nameWidth = maximum (0 : map (T.length . entryName) shown)
      tags = map (maybe T.empty (\c -> T.pack "[" <> c <> T.pack "]") . entryCategory) shown
      tagWidth = maximum (0 : map T.length tags)
      columns e tag =
        [T.justifyLeft nameWidth ' ' (entryName e)]
          ++ [T.justifyLeft tagWidth ' ' tag | tagWidth > 0]
          ++ [fromMaybe T.empty (entryLogin e)]
  when (null shown) $
    putStrLn (maybe "La bóveda está vacía." (const "No hay entradas en esa categoría.") only)
  sequence_
    [ putStrLn (colorPrefix tty (entryName e) <> T.unpack (T.stripEnd (T.intercalate (T.pack "  ") (columns e tag))))
    | (e, tag) <- zip shown tags
    ]

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

-- | La entrada a la que se refiere lo tecleado, aunque no sea el nombre exacto
-- ('matchEntries'). Si hay varias candidatas, pide elegir por número.
resolve :: MasterKey -> Text -> Vault -> IO Entry
resolve key query v = do
  es <- orDie (entries key v)
  case matchEntries query es of
    [] -> die (describe (EntryNotFound query))
    [e] -> pure e
    candidates -> do
      tty <- hIsTerminalDevice stdout
      sequence_ [putStrLn (show i <> ") " <> entryLine tty (entryName e)) | (i, e) <- zip [1 :: Int ..] candidates]
      answer <- readInput False ("¿Cuál? [1-" <> show (length candidates) <> "] ")
      case readMaybe . T.unpack . T.strip . T.pack =<< answer of
        Just i | i >= 1 && i <= length candidates -> pure (candidates !! (i - 1))
        _ -> die "Sin cambios."

-- | Usuario y categoría son opcionales; Enter sin escribir los deja vacíos.
askMeta :: IO (Maybe Text, Maybe Text)
askMeta = do
  login <- readInput False "Usuario o correo (opcional): "
  category <- readInput False "Categoría (opcional): "
  pure (T.pack <$> login, T.pack <$> category)

entryLine :: Bool -> Text -> String
entryLine tty name = colorPrefix tty name <> T.unpack name

colorPrefix :: Bool -> Text -> String
colorPrefix tty name = swatch tty color <> toHex color <> "  "
  where
    color = fingerprint name

-- | Muestra de color en terminales con truecolor; se omite al redirigir.
swatch :: Bool -> Oklch -> String
swatch False _ = ""
swatch True color = printf "\ESC[48;2;%d;%d;%dm    \ESC[0m " r g b
  where
    (r, g, b) = toSrgb color
