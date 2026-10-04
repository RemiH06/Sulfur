# Modelo de amenazas de Sulfur

Documento para quien revise la seguridad de Sulfur antes de que se use con contraseñas reales. Describe qué protege la herramienta, contra quién, con qué primitivas y dónde están los límites conocidos, para que la revisión pueda ir directo al código en vez de reconstruir el diseño.

Estado: versión 2.0 del CLI, formato de bóveda versión 2. Sin revisión externa todavía.

## Alcance

Sulfur es un gestor de contraseñas de línea de comandos para un solo usuario en su propia máquina. Tiene dos capas que no comparten material:

1. **Huella visual** (`src/Sulfur/Fingerprint.hs`): color derivado del nombre de una entrada. Es pública por diseño y no protege nada.
2. **Bóveda** (`src/Sulfur/Vault.hs`): archivo JSON con las entradas cifradas.

El CLI está en `app/Main.hs` y el generador de contraseñas en `src/Sulfur/Password.hs`. Las pruebas de propiedades que respaldan lo que se afirma aquí están en `test/Spec.hs`.

## Activos

| Activo | Dónde vive | Qué tan sensible |
|---|---|---|
| Secretos de las entradas | Cifrados en la bóveda; en claro solo en memoria y en la terminal al usar `get` | Alto |
| Contraseña maestra | Solo la teclea el usuario; nunca se guarda | Alto |
| Nombres de las entradas | Cifrados junto con el secreto | Medio: revelan en qué servicios hay cuenta |
| Número de entradas y su tamaño | Visibles en el archivo | Bajo |

## Adversarios

| Adversario | Capacidad | ¿En alcance? |
|---|---|---|
| **A1. Lector del archivo** | Obtiene una copia de `vault.json` (respaldo filtrado, disco robado, nube) | Sí |
| **A2. Escritor del archivo** | Puede modificar, borrar o reemplazar `vault.json`, pero no conoce la maestra | Sí, con las limitaciones de abajo |
| **A3. Observador de pantalla** | Ve la terminal o su historial de desplazamiento | Parcial |
| **A4. Proceso malicioso del mismo usuario** | Lee memoria, registra teclas, lee el portapapeles | No: fuera de alcance |
| **A5. Cadena de suministro** | Compromete una dependencia de Hackage | Mitigación parcial (versiones fijadas) |

## Diseño criptográfico

### Derivación de la clave

- Argon2id, versión 1.3 (`Crypto.KDF.Argon2` de `crypton`).
- Parámetros por default: 3 pasadas, 64 MiB, 4 carriles (RFC 9106, segunda opción recomendada). Se guardan en el archivo.
- Sal de 16 bytes aleatorios por bóveda. Salida de 32 bytes en `ScrubbedBytes`, que se borra al liberarse.
- La maestra se normaliza a Unicode NFC antes de derivar, para que la misma contraseña tecleada con o sin caracteres combinados dé la misma clave.
- Mínimo de 12 caracteres en el CLI; no hay estimación de fuerza.
- Al leer el archivo, los parámetros se acotan: 1 a 64 pasadas, 1 a 16 carriles, memoria entre 8 KiB por carril y 4 GiB, sal de al menos 16 bytes. Un archivo alterado no puede pedir una derivación arbitrariamente cara ni una sal corta.

### Cifrado de las entradas

- XChaCha20-Poly1305 (`Crypto.Cipher.ChaChaPoly1305`, `initializeX`).
- Nonce de 24 bytes aleatorios por cada sellado, del generador del sistema operativo (`getRandomBytes` en IO llama a `getEntropy`; en Windows, `CryptGenRandom`). Con 192 bits, la colisión es despreciable aunque se reutilice la clave indefinidamente.
- Texto plano de cada entrada: JSON `{"name": ..., "secret": ...}`. Nombre y secreto viajan juntos, así que el archivo no revela nombres.
- Formato de cada blob: `nonce (24) ‖ cifrado ‖ tag (16)`, en base64 dentro del JSON.
- La comparación del tag es de tiempo constante (`Eq` de `Poly1305.Auth` usa `constEq`). El texto descifrado solo se devuelve si el tag coincide (`open` en `Vault.hs`).

### Índice sellado

- Un blob adicional, el índice, sella la concatenación del SHA-256 de cada blob de entrada en orden.
- Abrirlo confirma la maestra aunque la bóveda esté vacía; si no abre, el error es `WrongPassword`.
- Cada lectura (`entries`) abre primero cada entrada y después compara el índice contra la lista tal como está. Esto detecta entradas borradas, reordenadas o reinsertadas desde una versión anterior de la misma bóveda (por ejemplo, el secreto previo a una rotación).
- Toda modificación pasa por `withBlobs`, que vuelve a sellar el índice.

### Separación de dominios

- AAD distinto para el índice (`sulfur-vault-v2-index`) y para las entradas (`sulfur-vault-v2-entry`), así un blob de un tipo no se acepta como el otro.
- Los campos del encabezado (versión, parámetros de Argon2, sal) no van en el AAD. Alterarlos cambia la clave derivada o hace fallar la lectura, así que el resultado es una bóveda que no abre, no una que abre con otro contenido.

### Huella visual

- SHA-256 del nombre en NFC, mapeado a OKLCH. No usa la clave ni la maestra.
- Como es un hash sin sal del nombre, **nunca se guarda en disco**: se calcula al mostrar. Guardarla junto a nombres cifrados permitiría confirmar nombres por diccionario.

## Qué se garantiza, por adversario

**A1, lector del archivo.** Solo ve el número de entradas, el tamaño de cada blob, los parámetros de Argon2 y la sal. Para obtener cualquier nombre o secreto necesita la maestra, y cada intento cuesta una derivación Argon2id completa.

**A2, escritor del archivo.**
- Alterar cualquier byte de una entrada se detecta (`TamperedEntry`).
- Borrar, reordenar o reinsertar blobs viejos se detecta (`TamperedIndex`).
- Bajar los parámetros de Argon2 no debilita nada: la clave cambia y la bóveda no abre.
- Puede impedir el uso (borrar o corromper el archivo). La disponibilidad no está en alcance.

**A3, observador de pantalla.** Las contraseñas se leen sin eco cuando la entrada es una consola real (`getPassword` de haskeline; verificado a mano en PowerShell el 4 de octubre de 2026, junto con que una maestra con "ñ" tecleada y mandada por pipe dan la misma clave, y que la página de códigos de la consola se restaura aunque se cancele con Ctrl+C). `get` solo escribe a una terminal y se niega a escribir a un archivo o pipe.

## Limitaciones conocidas

1. **Reversión del archivo completo.** Restaurar `vault.json` entero a una versión anterior y válida no se detecta. Requiere un contador monotónico guardado fuera del archivo; está pendiente porque perder ese contador bloquearía la bóveda.
2. **Las copias viejas siguen abriendo con la maestra vieja.** Después de `passwd`, cualquier respaldo previo de la bóveda se abre con la maestra anterior. Igual con entradas borradas o rotadas: siguen en los respaldos viejos.
3. **Longitud visible.** El cifrado no agrega relleno, así que el tamaño de cada blob delata la longitud de nombre más secreto (más 23 bytes fijos de JSON y los escapes que haga falta). Mitigación propuesta: rellenar el texto plano a múltiplos de un tamaño fijo antes de sellar.
4. **Secretos en memoria.** Solo la clave derivada vive en memoria que se borra. Los secretos pasan por `String` y `Text`, que el recolector de basura de GHC no borra al liberar.
5. **Historial de la terminal.** Lo que imprime `get` queda en el historial de desplazamiento de la terminal hasta que se limpie.
6. **Entrada por pipe.** Si la entrada no es una consola, se lee como UTF-8 sin ocultar nada. Mandar la maestra con `echo` o similares la deja en el historial del shell; es responsabilidad de quien lo haga.
7. **Git Bash (mintty).** No es una consola de Windows: las contraseñas se ven al teclear y `get` se niega a escribir.
8. **Dependencias.** `crypton`, `ram`, `aeson` y las demás están fijadas en `cabal.project.freeze`, pero no se han auditado como parte de este proyecto.

## Preguntas concretas para la revisión

1. ¿El índice sellado (SHA-256 por blob, concatenados y sellados con la misma clave) es suficiente para detectar borrado, reordenamiento y reinserción, o hay una combinación que se le escape?
2. ¿Es aceptable dejar el encabezado fuera del AAD, dado que alterarlo cambia la clave derivada? ¿Conviene autenticarlo de forma explícita?
3. ¿Los límites de Argon2 al leer son razonables, tanto contra un archivo que pida demasiado como contra uno que pida muy poco?
4. En `open`, el descifrado se evalúa de forma perezosa y el texto plano solo se devuelve si el tag coincide. ¿Hay alguna forma de que texto sin verificar salga del módulo?
5. ¿Vale la pena el relleno de la limitación 3, y con qué tamaño de bloque?
6. ¿Algún riesgo en normalizar la maestra a NFC antes de derivar?

## Cómo reproducir las verificaciones

```bash
cabal test --test-show-details=direct
```

Las garantías de A1 y A2 tienen una propiedad en `test/Spec.hs`, con nombres en español: "la maestra correcta abre y otra no", "cualquier byte alterado se detecta", "quitar o reordenar blobs a mano se detecta", "reinsertar un blob viejo (secreto anterior) se detecta", "el blob del índice no pasa por entrada", "alterar parámetros o sal del encabezado no abre" y "rechaza parámetros de Argon2 abusivos al leer". Las de A3 dependen de la terminal y no tienen prueba automática.
