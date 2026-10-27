{-# LANGUAGE CPP #-}

module Main (main) where

import Clipboard (copyTransient)
import Control.Exception (finally)
import Control.Monad (unless, when)
import Data.ByteArray (ScrubbedBytes)
import Data.ByteArray qualified as BA
import Data.List (sortOn)
import Data.Maybe (fromMaybe, isNothing)
import Data.Text (Text)
import Data.Text qualified as T
import Data.ByteString qualified as BS
import Data.Text.Encoding (decodeUtf8')
import Data.Word (Word8)
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (peekByteOff)
import Sulfur.Fingerprint
import Sulfur.Import (parseEntries)
import Sulfur.Password (generatePassword)
import Sulfur.Rollback (Seen (..), checkSeen, recordSeen)
import Sulfur.Search (matchEntries)
import Sulfur.Secret
import Sulfur.Vault
import System.Console.Haskeline
import System.Directory (XdgDirectory (XdgData, XdgState), canonicalizePath, doesFileExist, getTemporaryDirectory, getXdgDirectory, removeFile)
import System.Environment (getArgs, lookupEnv)
import System.Exit (die)
import System.FilePath (equalFilePath, splitDirectories, (</>))
import System.IO
import Text.Printf (printf)
import Text.Read (readMaybe)
#if defined(mingw32_HOST_OS)
import Data.Bits (complement, (.&.), (.|.))
import Data.Word (Word16, Word32)
import Foreign.C.Types (CInt (..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (nullPtr)
import Foreign.Storable (peek, peekElemOff)
import System.Win32.Console (getConsoleOutputCP, setConsoleOutputCP)
import System.Win32.MinTTY (isMinTTYHandle)
import System.Win32.Types (BOOL, DWORD, HANDLE, withHandleToHANDLE)
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
  tty <- isTerminal stdout
  let color = fingerprint text
  printf "%s%s  oklch(%.3f %.3f %.1f)\n" (swatch tty color) (toHex color)
    (lightness color) (chroma color) (hue color)

cmdInit :: IO ()
cmdInit = do
  path <- vaultPath
  exists <- doesFileExist path
  when exists $ die ("Ya existe una bóveda en " <> path)
  temp <- inTempDir path
  when temp $ do
    ok <- confirm (tempWarning path <> " ¿Crearla de todos modos? [s/N] ")
    unless ok $ die "Sin cambios. Apunta SULFUR_VAULT a otra carpeta, por ejemplo %APPDATA%\\sulfur."
  password <- askNewMaster
  (v, _) <- newVault defaultKdf password >>= orDie
  save path v
  putStrLn ("Bóveda creada en " <> path)

cmdAdd :: Text -> IO ()
cmdAdd name = do
  when (T.null (T.strip name)) $ die "El nombre no puede estar vacío."
  (path, v, key) <- openVault
  secret <- askNew "Secreto: " "Repítelo: "
  (login, category) <- askMeta
  v' <- addEntry key (Entry name secret login category) v >>= orDie
  save path v'
  tty <- isTerminal stdout
  putStrLn (entryLine tty name)

-- | Solo escribe a una terminal: redirigido, el secreto acabaría en un
-- archivo o en otro proceso.
cmdGet :: Text -> IO ()
cmdGet query = do
  tty <- isTerminal stdout
  unless tty $ die "get solo escribe en una terminal, nunca a un archivo o pipe."
  (_, v, key) <- openVault
  e <- resolve key query v
  when (entryName e /= query) $ putStrLn (entryLine tty (entryName e))
  putSecretLn (entrySecret e)

-- | Los bytes del secreto tal cual (ya son UTF-8 y la consola está en UTF-8),
-- sin pasar por 'String'.
putSecretLn :: Secret -> IO ()
putSecretLn s = do
  hFlush stdout
  BA.withByteArray (secretBytes s) $ \p -> hPutBuf stdout (p :: Ptr Word8) (BA.length (secretBytes s))
  putStrLn ""

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
  save path v'
  tty <- isTerminal stdout
  putStrLn (entryLine tty name)

cmdEdit :: Text -> IO ()
cmdEdit query = do
  (path, v, key) <- openVault
  name <- entryName <$> resolve key query v
  secret <- askNew ("Secreto nuevo para " <> T.unpack name <> ": ") "Repítelo: "
  v' <- replaceSecret key name secret v >>= orDie
  save path v'
  tty <- isTerminal stdout
  putStrLn (entryLine tty name)

cmdRemove :: Text -> IO ()
cmdRemove query = do
  (path, v, key) <- openVault
  name <- entryName <$> resolve key query v
  v' <- removeEntry key name v >>= orDie
  ok <- confirm ("¿Borrar " <> T.unpack name <> "? No se puede deshacer. [s/N] ")
  unless ok $ die "Sin cambios."
  save path v'
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
  save path v'
  tty <- isTerminal stdout
  putStrLn (entryLine tty name)

-- | Muestra la huella anterior y la nueva: al cambiar el nombre cambia el color.
cmdRename :: Text -> Text -> IO ()
cmdRename query new = do
  when (T.null (T.strip new)) $ die "El nombre no puede estar vacío."
  (path, v, key) <- openVault
  old <- entryName <$> resolve key query v
  v' <- renameEntry key old new v >>= orDie
  save path v'
  tty <- isTerminal stdout
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
  save path v'
  tty <- isTerminal stdout
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
  save path v'
  let backup = backupPath path
  hasBackup <- doesFileExist backup
  when hasBackup $ removeFile backup
  putStrLn "Contraseña maestra cambiada. Las copias que tengas en otro lado siguen abriendo con la maestra vieja."

-- | Agrupa por categoría (las que no tienen van al final) y alinea columnas.
cmdList :: Maybe Text -> IO ()
cmdList only = do
  (_, v, key) <- openVault
  es <- orDie (entries key v)
  tty <- isTerminal stdout
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

-- | Windows vacía la carpeta temporal por su cuenta (Sensor de almacenamiento),
-- así que una bóveda ahí se pierde sin aviso.
inTempDir :: FilePath -> IO Bool
inTempDir path = do
  temp <- splitDirectories <$> (canonicalizePath =<< getTemporaryDirectory)
  full <- splitDirectories <$> canonicalizePath path
  pure (length temp <= length full && and (zipWith equalFilePath temp full))

tempWarning :: FilePath -> String
tempWarning path = path <> " está en la carpeta temporal, que Windows vacía por su cuenta."

openVault :: IO (FilePath, Vault, MasterKey)
openVault = do
  path <- vaultPath
  exists <- doesFileExist path
  unless exists $ die ("No hay bóveda en " <> path <> ". Créala con: sulfur init")
  temp <- inTempDir path
  when temp $ hPutStrLn stderr (tempWarning path <> " Muévela a otra carpeta y actualiza SULFUR_VAULT.")
  bytes <- BS.readFile path
  v <- orDie (decodeVault bytes)
  dir <- seenDir
  seen <- checkSeen dir path bytes
  when (seen == ChangedOutside) $ do
    ok <- confirm $
      "La bóveda cambió fuera de Sulfur desde la última vez. Si restauraste un respaldo"
        <> " o la copiaste de otro equipo, es normal; si no, alguien pudo regresarla a una"
        <> " versión vieja. ¿Aceptarla como la actual? [s/N] "
    unless ok $ die "Sin cambios. La bóveda no se abrió."
  password <- askSecret "Contraseña maestra: "
  key <- orDie (unlock password v)
  when (seen == FirstTime) $
    hPutStrLn stderr "Primera vez que se abre esta bóveda en este equipo; desde ahora Sulfur avisa si cambia por fuera."
  unless (seen == Unchanged) $ recordSeen dir path bytes
  if vaultFormat v == currentFormat
    then pure (path, v, key)
    else do
      v' <- upgrade key v >>= orDie
      save path v'
      hPutStrLn stderr $
        "Bóveda convertida al formato " <> show currentFormat <> " (secretos fuera de JSON)."
          <> " La versión anterior quedó en " <> backupPath path <> "."
      pure (path, v', key)

-- | Guarda y registra el archivo resultante como el último que dejó Sulfur
-- ('checkSeen').
save :: FilePath -> Vault -> IO ()
save path v = do
  saveVault path v
  dir <- seenDir
  recordSeen dir path =<< BS.readFile path

-- | Fuera de la carpeta de la bóveda (%LOCALAPPDATA%\sulfur\vistas en
-- Windows), para que reemplazar la carpeta entera no se lleve el registro.
seenDir :: IO FilePath
seenDir = (</> "vistas") <$> getXdgDirectory XdgState "sulfur"

-- | Si un handle llega a una terminal. La de Git Bash (mintty) no es una
-- consola de Windows sino un pipe con nombre, así que se reconoce aparte.
isTerminal :: Handle -> IO Bool
#if defined(mingw32_HOST_OS)
isTerminal h = (||) <$> hIsTerminalDevice h <*> withHandleToHANDLE h isMinTTYHandle
#else
isTerminal = hIsTerminalDevice
#endif

-- | Lee una línea visible (confirmaciones, usuario, categoría, elegir entre
-- candidatas). En una consola real usa haskeline, que lee Unicode con la API
-- de Windows; sin historial ni autocompletado, así que nada se escribe a
-- disco. Si la entrada no es una consola (pipe, Git Bash), haskeline
-- decodificaría con la página de códigos del sistema, así que ahí se lee la
-- línea en bytes y se decodifica como UTF-8.
readInput :: String -> IO (Maybe Text)
readInput label = do
  console <- hIsTerminalDevice stdin
  if console
    then fmap T.pack <$> runInputT quiet (getInputLine label)
    else do
      prompt label
      line <- readLineBytes
      traverse (either (const (die "La entrada no está en UTF-8.")) pure . decodeUtf8' . BA.convert) line
  where
    quiet = Settings {complete = noCompletion, historyFile = Nothing, autoAddHistory = False}

prompt :: String -> IO ()
prompt label = putStr label >> hFlush stdout

-- | Lee un secreto sin pasar por 'String' ni 'Text' (haskeline los devuelve
-- como 'String'). En una consola, sin eco ('readHidden'); si no (pipe, Git
-- Bash), la línea en bytes y sin ocultar nada.
askSecret :: String -> IO Secret
askSecret label = do
  console <- hIsTerminalDevice stdin
  prompt label
  raw <- if console then readHidden else readLineBytes
  bytes <- maybe (die "Entrada cancelada.") pure raw
  maybe (die "La entrada no está en UTF-8.") pure (secretFromUtf8 bytes)

-- | Más de lo que mide cualquier contraseña razonable; el búfer se reserva
-- completo para no copiar el secreto al crecer.
maxLine :: Int
maxLine = 4096

-- | Una línea de stdin, byte por byte y directo a 'ScrubbedBytes', sin el
-- salto ni el `\r` de CRLF. 'Nothing' si stdin se acabó antes de leer algo.
-- Todo lo que no viene de una consola pasa por aquí, para no mezclar lecturas
-- de bytes y de caracteres en el mismo handle.
readLineBytes :: IO (Maybe ScrubbedBytes)
readLineBytes = do
  (len, buf) <- BA.allocRet maxLine (go 0) :: IO (Maybe Int, ScrubbedBytes)
  pure ((`BA.take` buf) <$> len)
  where
    go :: Int -> Ptr Word8 -> IO (Maybe Int)
    go n p
      | n >= maxLine = die "La línea es demasiado larga."
      | otherwise = do
          got <- hGetBuf stdin (p `plusPtr` n) 1
          if got == 0
            then pure (if n == 0 then Nothing else Just n)
            else do
              b <- peekByteOff p n :: IO Word8
              if b /= 10
                then go (n + 1) p
                else do
                  previous <- if n > 0 then peekByteOff p (n - 1) else pure (0 :: Word8)
                  pure (Just (if previous == 13 then n - 1 else n))

-- | Sin eco. En Windows también sin el modo de línea de la consola, porque en
-- ese modo la consola guarda lo tecleado en su historial (flecha arriba, F7)
-- aunque no se vea: se lee tecla por tecla en UTF-16, directo a
-- 'ScrubbedBytes', y se convierte a UTF-8 con WideCharToMultiByte. Retroceso
-- borra, Enter termina y Ctrl+C cancela.
readHidden :: IO (Maybe ScrubbedBytes)
#if defined(mingw32_HOST_OS)
readHidden = withHandleToHANDLE stdin $ \h -> do
  mode <- alloca $ \p -> c_GetConsoleMode h p >> peek p
  let raw = mode .&. complement (enableProcessedInput .|. enableLineInput .|. enableEchoInput)
  (units, wide) <-
    (c_SetConsoleMode h raw >> BA.allocRet (maxLine * 2) (keys h 0) :: IO (Maybe Int, ScrubbedBytes))
      `finally` c_SetConsoleMode h mode
  putStrLn ""
  traverse (toUtf8 wide) units
  where
    enableProcessedInput = 0x1
    enableLineInput = 0x2
    enableEchoInput = 0x4

keys :: HANDLE -> Int -> Ptr Word16 -> IO (Maybe Int)
keys h n buf
  | n >= maxLine = die "La línea es demasiado larga."
  | otherwise = do
      got <- alloca $ \readPtr -> do
        ok <- c_ReadConsoleW h (buf `plusPtr` (n * 2)) 1 readPtr nullPtr
        unless ok $ die "No se pudo leer la consola."
        peek readPtr
      c <- peekElemOff buf n
      case (got, c) of
        (0, _) -> keys h n buf
        (_, 13) -> pure (Just n)
        (_, 10) -> pure (Just n)
        (_, 3) -> pure Nothing
        (_, 8) -> do
          -- Un carácter fuera del plano básico ocupa dos unidades (sustitutos).
          previous <- if n > 0 then peekElemOff buf (n - 1) else pure 0
          keys h (max 0 (if n >= 2 && previous >= 0xDC00 && previous <= 0xDFFF then n - 2 else n - 1)) buf
        _ -> keys h (n + 1) buf

-- | Rechaza sustitutos sueltos en vez de cambiarlos por U+FFFD.
toUtf8 :: ScrubbedBytes -> Int -> IO ScrubbedBytes
toUtf8 _ 0 = pure BA.empty
toUtf8 wide units = BA.withByteArray wide $ \src -> do
  size <- c_WideCharToMultiByte cpUtf8 wcErrInvalidChars src (fromIntegral units) nullPtr 0 nullPtr nullPtr
  when (size == 0) $ die "La entrada no es Unicode válido."
  BA.alloc (fromIntegral size) $ \dst -> do
    _ <- c_WideCharToMultiByte cpUtf8 wcErrInvalidChars src (fromIntegral units) dst size nullPtr nullPtr
    pure ()
  where
    cpUtf8 = 65001
    wcErrInvalidChars = 0x80

foreign import ccall unsafe "windows.h GetConsoleMode" c_GetConsoleMode :: HANDLE -> Ptr DWORD -> IO BOOL
foreign import ccall unsafe "windows.h SetConsoleMode" c_SetConsoleMode :: HANDLE -> DWORD -> IO BOOL
foreign import ccall safe "windows.h ReadConsoleW"
  c_ReadConsoleW :: HANDLE -> Ptr Word16 -> DWORD -> Ptr DWORD -> Ptr () -> IO BOOL
foreign import ccall unsafe "windows.h WideCharToMultiByte"
  c_WideCharToMultiByte :: Word32 -> DWORD -> Ptr Word16 -> CInt -> Ptr Word8 -> CInt -> Ptr Word8 -> Ptr BOOL -> IO CInt
#else
readHidden = do
  echo <- hGetEcho stdin
  line <- (hSetEcho stdin False >> readLineBytes) `finally` hSetEcho stdin echo
  putStrLn ""
  pure line
#endif

askNew :: String -> String -> IO Secret
askNew label confirmLabel = do
  first <- askSecret label
  when (nullSecret first) $ die "No puede estar vacío."
  second <- askSecret confirmLabel
  unless (first == second) $ die "No coinciden."
  pure first

askNewMaster :: IO Secret
askNewMaster = do
  password <- askNew "Contraseña maestra nueva: " "Repítela: "
  when (secretLength password < 12) $ die "La contraseña maestra debe tener al menos 12 caracteres."
  pure password

confirm :: String -> IO Bool
confirm question = do
  answer <- readInput question
  pure (maybe False ((`elem` map T.pack ["s", "si", "sí"]) . T.toLower . T.strip) answer)

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
      tty <- isTerminal stdout
      sequence_ [putStrLn (show i <> ") " <> entryLine tty (entryName e)) | (i, e) <- zip [1 :: Int ..] candidates]
      answer <- readInput ("¿Cuál? [1-" <> show (length candidates) <> "] ")
      case readMaybe . T.unpack . T.strip =<< answer of
        Just i | i >= 1 && i <= length candidates -> pure (candidates !! (i - 1))
        _ -> die "Sin cambios."

-- | Usuario y categoría son opcionales; Enter sin escribir los deja vacíos.
askMeta :: IO (Maybe Text, Maybe Text)
askMeta = do
  login <- readInput "Usuario o correo (opcional): "
  category <- readInput "Categoría (opcional): "
  pure (login, category)

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
