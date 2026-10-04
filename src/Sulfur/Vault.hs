{-# LANGUAGE OverloadedStrings #-}

-- | Bóveda: cifrado real de las entradas. Clave derivada de la contraseña
-- maestra con Argon2id y cada entrada sellada con XChaCha20-Poly1305 y nonce
-- aleatorio propio. Nombre y secreto viajan cifrados juntos, así que el archivo
-- no revela en qué servicios hay cuenta. Nada de aquí toca la huella visual.
module Sulfur.Vault
  ( Vault (..)
  , Entry (..)
  , newEntry
  , normalizeEntry
  , inCategory
  , KdfParams (..)
  , MasterKey
  , VaultError (..)
  , defaultKdf
  , newVault
  , unlock
  , entries
  , lookupEntry
  , addEntry
  , replaceSecret
  , setLogin
  , setCategory
  , renameEntry
  , removeEntry
  , changeMaster
  , addEntries
  , pad
  , unpad
  , encodeVault
  , decodeVault
  , loadVault
  , saveVault
  ) where

import Control.Monad (unless, when)
import Crypto.Cipher.ChaChaPoly1305 qualified as C
import Crypto.Error (CryptoFailable (..), throwCryptoError)
import Crypto.Hash (Digest, SHA256, hash)
import Crypto.KDF.Argon2 qualified as Argon2
import Crypto.MAC.Poly1305 qualified as Poly1305
import Crypto.Random (getRandomBytes)
import Data.Aeson
import Data.Aeson.Types (Parser)
import Data.ByteArray (ScrubbedBytes)
import Data.ByteArray qualified as BA
import Data.ByteArray.Encoding (Base (Base64), convertFromBase, convertToBase)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.List (find)
import Data.Maybe (catMaybes)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (decodeLatin1, encodeUtf8)
import Data.Text.Normalize (NormalizationMode (NFC), normalize)
import Data.Word (Word32)
import System.Directory (createDirectoryIfMissing, renameFile)
import System.FilePath (takeDirectory)

data KdfParams = KdfParams
  { kdfIterations :: Word32
  , kdfMemoryKiB :: Word32
  , kdfParallelism :: Word32
  }
  deriving (Eq, Show)

-- | RFC 9106, segunda opción recomendada: 3 pasadas, 64 MiB, 4 carriles.
defaultKdf :: KdfParams
defaultKdf = KdfParams 3 65536 4

-- | Todo lo que se guarda en disco. Los blobs son nonce ‖ cifrado ‖ tag.
data Vault = Vault
  { vaultKdf :: KdfParams
  , vaultSalt :: ByteString
  , vaultIndex :: ByteString
  -- ^ SHA-256 de cada blob de entrada, en orden, sellado. Abrirlo confirma la
  -- maestra aunque no haya entradas, y amarra la lista completa: borrar,
  -- reordenar o reinsertar un blob viejo (válido, de la misma clave) deja de
  -- coincidir.
  , vaultEntries :: [ByteString]
  }
  deriving (Eq, Show)

-- | Usuario y categoría viajan cifrados con el resto: el archivo tampoco
-- revela qué correo se usa en cada cuenta.
data Entry = Entry
  { entryName :: Text
  , entrySecret :: Text
  , entryLogin :: Maybe Text
  -- ^ Correo o usuario con el que se entra a la cuenta.
  , entryCategory :: Maybe Text
  }
  deriving (Eq, Show)

newEntry :: Text -> Text -> Entry
newEntry name secret = Entry name secret Nothing Nothing

-- | Forma en que se guarda una entrada: nombre y categoría en NFC (para que
-- buscar y filtrar no dependan de cómo se escribieron), usuario y categoría
-- sin espacios a los lados, y vacío como ausente. El secreto no se toca.
normalizeEntry :: Entry -> Entry
normalizeEntry e =
  e
    { entryName = normalize NFC (entryName e)
    , entryLogin = cleanMeta (entryLogin e)
    , entryCategory = cleanMeta (entryCategory e)
    }

-- | Sin distinguir mayúsculas ni la forma Unicode en que se escribió.
inCategory :: Text -> Entry -> Bool
inCategory category e = (fold <$> cleanMeta (Just category)) == (fold <$> entryCategory e)
  where
    fold = T.toCaseFold . normalize NFC

cleanMeta :: Maybe Text -> Maybe Text
cleanMeta m = case normalize NFC . T.strip <$> m of
  Just t | not (T.null t) -> Just t
  _ -> Nothing

-- | Clave de 32 bytes en memoria que se borra al liberarse. Opaca a propósito.
newtype MasterKey = MasterKey C.Key

data VaultError
  = WrongPassword
  | TamperedEntry
  | TamperedIndex
  | CorruptEntry
  | DuplicateName Text
  | EntryNotFound Text
  | InvalidFile String
  | InvalidKdfParams
  deriving (Eq, Show)

-- Dato asociado distinto para el índice y para las entradas, para que un blob
-- de un tipo no pueda hacerse pasar por el otro.
indexAad, entryAad :: ByteString
indexAad = "sulfur-vault-v3-index"
entryAad = "sulfur-vault-v3-entry"

-- | El texto plano de cada entrada se lleva al siguiente múltiplo de 256
-- bytes: las entradas comunes miden lo mismo en disco y el tamaño ya no delata
-- la longitud de nombre y secreto.
padBlock :: Int
padBlock = 256

-- | Relleno ISO/IEC 7816-4: un byte 0x80 y ceros hasta el múltiplo. Siempre
-- agrega al menos un byte, así que quitarlo nunca es ambiguo.
pad :: ByteString -> ByteString
pad bs = bs <> BS.cons 0x80 (BS.replicate zeros 0)
  where
    zeros = (padBlock - (BS.length bs + 1) `mod` padBlock) `mod` padBlock

unpad :: ByteString -> Maybe ByteString
unpad bs = case BS.unsnoc (BS.dropWhileEnd (== 0) bs) of
  Just (body, 0x80) -> Just body
  _ -> Nothing

nonceLen, tagLen :: Int
nonceLen = 24
tagLen = 16

-- | La maestra se normaliza a NFC por la misma razón que la huella: la misma
-- contraseña escrita con o sin caracteres combinados debe abrir la bóveda.
deriveKey :: KdfParams -> ByteString -> Text -> Either VaultError MasterKey
deriveKey p salt password =
  case Argon2.hash opts (encodeUtf8 (normalize NFC password)) salt 32 of
    CryptoPassed (raw :: ScrubbedBytes) -> Right (MasterKey (throwCryptoError (C.key raw)))
    CryptoFailed _ -> Left InvalidKdfParams
  where
    opts =
      Argon2.Options
        { Argon2.iterations = kdfIterations p
        , Argon2.memory = kdfMemoryKiB p
        , Argon2.parallelism = kdfParallelism p
        , Argon2.variant = Argon2.Argon2id
        , Argon2.version = Argon2.Version13
        }

seal :: MasterKey -> ByteString -> ByteString -> IO ByteString
seal (MasterKey k) aad plain = do
  nonceBytes <- getRandomBytes nonceLen
  let st = C.finalizeAAD (C.appendAAD aad (C.initializeX k (throwCryptoError (C.nonce24 nonceBytes))))
      (cipher, st') = C.encrypt plain st
  pure (nonceBytes <> cipher <> BA.convert (C.finalize st'))

-- | 'Nothing' si el tag no coincide: clave equivocada o blob alterado.
open :: MasterKey -> ByteString -> ByteString -> Maybe ByteString
open (MasterKey k) aad blob
  | BS.length blob < nonceLen + tagLen = Nothing
  | otherwise = case Poly1305.authTag tagBytes of
      CryptoPassed tag | tag == C.finalize st' -> Just plain
      _ -> Nothing
  where
    (nonceBytes, rest) = BS.splitAt nonceLen blob
    (cipher, tagBytes) = BS.splitAt (BS.length rest - tagLen) rest
    st = C.finalizeAAD (C.appendAAD aad (C.initializeX k (throwCryptoError (C.nonce24 nonceBytes))))
    (plain, st') = C.decrypt cipher st

digestList :: [ByteString] -> ByteString
digestList = BS.concat . map (\b -> BA.convert (hash b :: Digest SHA256))

-- | Única forma de cambiar las entradas: siempre vuelve a sellar el índice.
withBlobs :: MasterKey -> [ByteString] -> Vault -> IO Vault
withBlobs key blobs v = do
  index <- seal key indexAad (digestList blobs)
  pure v {vaultIndex = index, vaultEntries = blobs}

newVault :: KdfParams -> Text -> IO (Either VaultError (Vault, MasterKey))
newVault p password = do
  salt <- getRandomBytes 16
  case deriveKey p salt password of
    Left err -> pure (Left err)
    Right key -> Right . (,key) <$> withBlobs key [] (Vault p salt BS.empty [])

unlock :: Text -> Vault -> Either VaultError MasterKey
unlock password v = do
  key <- deriveKey (vaultKdf v) (vaultSalt v) password
  maybe (Left WrongPassword) (const (Right key)) (open key indexAad (vaultIndex v))

-- | Primero cada entrada (un byte alterado da 'TamperedEntry'), después el
-- índice contra la lista tal como está ('TamperedIndex').
entries :: MasterKey -> Vault -> Either VaultError [Entry]
entries key v = do
  es <- traverse openEntry (vaultEntries v)
  case open key indexAad (vaultIndex v) of
    Just digests | digests == digestList (vaultEntries v) -> Right es
    _ -> Left TamperedIndex
  where
    openEntry blob = do
      plain <- maybe (Left TamperedEntry) Right (open key entryAad blob)
      maybe (Left CorruptEntry) Right (decodeStrict =<< unpad plain)

-- | Posición del blob cuya entrada se llama así (comparando en NFC).
locate :: MasterKey -> Text -> Vault -> Either VaultError (Int, Entry)
locate key name v = do
  es <- entries key v
  maybe (Left (EntryNotFound normalized)) Right $
    find ((== normalized) . entryName . snd) (zip [0 ..] es)
  where
    normalized = normalize NFC name

lookupEntry :: MasterKey -> Text -> Vault -> Either VaultError Entry
lookupEntry key name v = snd <$> locate key name v

sealEntry :: MasterKey -> Entry -> IO ByteString
sealEntry key = seal key entryAad . pad . LBS.toStrict . encode

-- | Se guarda normalizada ('normalizeEntry').
addEntry :: MasterKey -> Entry -> Vault -> IO (Either VaultError Vault)
addEntry key e = addEntries key [e]

-- | Todas o ninguna: un nombre repetido, contra la bóveda o dentro de la misma
-- lista, cancela la operación completa.
addEntries :: MasterKey -> [Entry] -> Vault -> IO (Either VaultError Vault)
addEntries key new v = case entries key v of
  Left err -> pure (Left err)
  Right existing -> case firstDuplicate (map entryName (existing ++ normalized)) of
    Just dup -> pure (Left (DuplicateName dup))
    Nothing -> do
      blobs <- mapM (sealEntry key) normalized
      Right <$> withBlobs key (vaultEntries v ++ blobs) v
  where
    normalized = map normalizeEntry new
    firstDuplicate [] = Nothing
    firstDuplicate (x : xs) = if x `elem` xs then Just x else firstDuplicate xs

-- | Vuelve a sellar, con nonce nuevo y en la misma posición, la entrada que se
-- llama así; las demás no se tocan.
modifyEntry :: MasterKey -> Text -> (Entry -> Entry) -> Vault -> IO (Either VaultError Vault)
modifyEntry key name f v = case locate key name v of
  Left err -> pure (Left err)
  Right (i, e) -> do
    blob <- sealEntry key (normalizeEntry (f e))
    let (before, after) = splitAt i (vaultEntries v)
    Right <$> withBlobs key (before ++ blob : drop 1 after) v

replaceSecret :: MasterKey -> Text -> Text -> Vault -> IO (Either VaultError Vault)
replaceSecret key name secret = modifyEntry key name (\e -> e {entrySecret = secret})

-- | 'Nothing' o texto vacío borra el dato.
setLogin, setCategory :: MasterKey -> Text -> Maybe Text -> Vault -> IO (Either VaultError Vault)
setLogin key name login = modifyEntry key name (\e -> e {entryLogin = login})
setCategory key name category = modifyEntry key name (\e -> e {entryCategory = category})

-- | El secreto, el usuario y la categoría no cambian.
renameEntry :: MasterKey -> Text -> Text -> Vault -> IO (Either VaultError Vault)
renameEntry key old new v = case entries key v of
  Left err -> pure (Left err)
  Right existing
    | normalized `elem` map entryName existing -> pure (Left (DuplicateName normalized))
    | otherwise -> modifyEntry key old (\e -> e {entryName = normalized}) v
  where
    normalized = normalize NFC new

removeEntry :: MasterKey -> Text -> Vault -> IO (Either VaultError Vault)
removeEntry key name v = case locate key name v of
  Left err -> pure (Left err)
  Right (i, _) -> do
    let (before, after) = splitAt i (vaultEntries v)
    Right <$> withBlobs key (before ++ drop 1 after) v

-- | Bóveda nueva (sal e índice nuevos) con las mismas entradas selladas
-- bajo la clave derivada de la maestra nueva.
changeMaster :: MasterKey -> KdfParams -> Text -> Vault -> IO (Either VaultError (Vault, MasterKey))
changeMaster key p password v = case entries key v of
  Left err -> pure (Left err)
  Right es -> do
    created <- newVault p password
    case created of
      Left err -> pure (Left err)
      Right (fresh, key') -> do
        blobs <- mapM (sealEntry key') es
        Right . (,key') <$> withBlobs key' blobs fresh

-- | Usuario y categoría son opcionales y se omiten si no hay: las entradas
-- guardadas antes de que existieran se siguen leyendo igual.
instance ToJSON Entry where
  toJSON (Entry n s l c) =
    object (["name" .= n, "secret" .= s] ++ catMaybes [("login" .=) <$> l, ("category" .=) <$> c])

instance FromJSON Entry where
  parseJSON = withObject "Entry" $ \o ->
    Entry <$> o .: "name" <*> o .: "secret" <*> o .:? "login" <*> o .:? "category"

instance ToJSON Vault where
  toJSON v =
    object
      [ "version" .= (3 :: Int)
      , "kdf"
          .= object
            [ "algorithm" .= ("argon2id" :: Text)
            , "iterations" .= kdfIterations (vaultKdf v)
            , "memoryKiB" .= kdfMemoryKiB (vaultKdf v)
            , "parallelism" .= kdfParallelism (vaultKdf v)
            ]
      , "salt" .= b64 (vaultSalt v)
      , "index" .= b64 (vaultIndex v)
      , "entries" .= map b64 (vaultEntries v)
      ]

-- | Los parámetros de Argon2 vienen del archivo, así que se acotan: un archivo
-- alterado no debe poder pedir gigas de memoria ni bajar la sal de 16 bytes.
instance FromJSON Vault where
  parseJSON = withObject "Vault" $ \o -> do
    version <- o .: "version"
    when (version == (1 :: Int)) $ fail "formato 1, anterior al índice sellado: crea la bóveda de nuevo"
    when (version == 2) $ fail "formato 2, anterior al relleno de longitud: crea la bóveda de nuevo"
    unless (version == 3) $ fail "versión de bóveda no soportada"
    kdf <- o .: "kdf"
    algorithm <- kdf .: "algorithm"
    unless (algorithm == ("argon2id" :: Text)) $ fail "algoritmo de derivación no soportado"
    p <- KdfParams <$> kdf .: "iterations" <*> kdf .: "memoryKiB" <*> kdf .: "parallelism"
    when (kdfIterations p < 1 || kdfIterations p > 64) $ fail "iteraciones fuera de rango"
    when (kdfParallelism p < 1 || kdfParallelism p > 16) $ fail "paralelismo fuera de rango"
    when (kdfMemoryKiB p < 8 * kdfParallelism p || kdfMemoryKiB p > 4194304) $ fail "memoria fuera de rango"
    salt <- unb64 =<< o .: "salt"
    when (BS.length salt < 16) $ fail "sal demasiado corta"
    Vault p salt <$> (unb64 =<< o .: "index") <*> (traverse unb64 =<< o .: "entries")

b64 :: ByteString -> Text
b64 = decodeLatin1 . convertToBase Base64

unb64 :: Text -> Parser ByteString
unb64 = either fail pure . convertFromBase Base64 . encodeUtf8

encodeVault :: Vault -> LBS.ByteString
encodeVault = encode

decodeVault :: ByteString -> Either VaultError Vault
decodeVault = either (Left . InvalidFile) Right . eitherDecodeStrict

loadVault :: FilePath -> IO (Either VaultError Vault)
loadVault path = decodeVault <$> BS.readFile path

-- | Escribe a un temporal y lo renombra encima, para que un corte a medio
-- guardar no deje la bóveda truncada.
saveVault :: FilePath -> Vault -> IO ()
saveVault path v = do
  createDirectoryIfMissing True (takeDirectory path)
  let tmp = path <> ".tmp"
  LBS.writeFile tmp (encodeVault v)
  renameFile tmp path
