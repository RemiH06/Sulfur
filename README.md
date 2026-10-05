![Haskell](https://img.shields.io/badge/-Haskell-5D4F85?style=for-the-badge&logo=haskell&logoColor=white)

```ascii
███████╗██╗   ██╗██╗     ███████╗██╗   ██╗██████╗
██╔════╝██║   ██║██║     ██╔════╝██║   ██║██╔══██╗
███████╗██║   ██║██║     █████╗  ██║   ██║██████╔╝
╚════██║██║   ██║██║     ██╔══╝  ██║   ██║██╔══██╗
███████║╚██████╔╝███████╗██║     ╚██████╔╝██║  ██║
╚══════╝ ╚═════╝ ╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝

       by Hex (@RemiH06)          version 2.0
```

![GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)

## Resumen

### Descripción general

Sulfur convierte texto en color de forma determinista: el mismo texto siempre da el mismo color. Sobre esa idea está construyendo un gestor de contraseñas de línea de comandos, donde cada entrada se reconoce de un vistazo por su color.

El proyecto separa dos capas que nunca se mezclan. La **huella visual** es pública: un color OKLCH derivado del SHA-256 del nombre de la entrada, sin ningún secreto de por medio. La **bóveda** es el cifrado real: la clave se deriva de la contraseña maestra con Argon2id y cada entrada (nombre y secreto juntos) se sella con XChaCha20-Poly1305 y un nonce aleatorio propio, así que el archivo no revela ni siquiera en qué servicios hay cuenta.

La versión 1.0 era un experimento en Kotlin sin valor de seguridad. Se conserva como referencia en `legacy/kotlin/`.

```diff
- La bóveda no ha tenido revisión externa. No la uses con contraseñas reales todavía.
- La huella visual no protege nada: cualquiera puede calcular el color de un nombre. Sirve para reconocer, no para autenticar.
- No detecta si alguien restaura el archivo completo a una versión anterior.
```

El diseño criptográfico, los adversarios considerados y las limitaciones conocidas están en [docs/modelo-de-amenazas.md](docs/modelo-de-amenazas.md).

## Installation

1. Instala la toolchain de Haskell con [GHCup](https://www.haskell.org/ghcup/) (GHC 9.10 y cabal 3.16 o posteriores).
2. Compila y corre las pruebas:
   ```bash
   cabal build
   cabal test
   ```
3. Instala el ejecutable en el `installdir` de cabal:
   ```bash
   cabal install exe:sulfur
   ```

## Launch arguments

- `sulfur color "<texto>"` huella visual de cualquier texto, en hex y OKLCH.
- `sulfur init` crea la bóveda; pide una contraseña maestra de al menos 12 caracteres.
- `sulfur add "<nombre>"` agrega una entrada con un secreto tecleado.
- `sulfur gen "<nombre>" [longitud]` genera el secreto (24 caracteres por default, de 12 a 128). Si la entrada existe, lo reemplaza tras confirmar.
- `sulfur copy "<nombre>"` copia el secreto al portapapeles por 30 segundos, marcado para que Windows no lo guarde en el historial (Win+V) ni lo suba a la nube, y lo vacía al terminar o con Ctrl+C. Si copiaste otra cosa en ese tiempo, no la toca. Solo en Windows.
- `sulfur get "<nombre>"` muestra el secreto. Solo escribe a una terminal, nunca a un archivo o pipe.
- `sulfur edit "<nombre>"` cambia el secreto por uno tecleado.
- `sulfur mv "<nombre>" "<nuevo>"` renombra una entrada; su color cambia con el nombre.
- `sulfur rm "<nombre>"` borra una entrada tras confirmar.
- `sulfur list [categoría]` lista las entradas con su huella, categoría y usuario, agrupadas por categoría. Con una categoría, filtra (sin distinguir mayúsculas).
- `sulfur set "<nombre>" usuario "<valor>"` y `sulfur set "<nombre>" categoria "<valor>"` cambian el correo o usuario y la categoría de una entrada; `""` los borra. `add` y `gen` los preguntan al crear una entrada, y se pueden dejar vacíos.
- `sulfur passwd` cambia la contraseña maestra y vuelve a cifrar todas las entradas.
- `sulfur import "<archivo>"` carga muchas entradas de un archivo con una línea `nombre=secreto` por entrada (el secreto se toma literal, sin comillas). Un encabezado `[categoría | correo]` aplica a las entradas de abajo hasta el siguiente. Importa todas o ninguna y al final ofrece borrar el archivo, que tiene los secretos en claro. Escríbelo fuera de carpetas sincronizadas o respaldadas, y no lo edites en VS Code (su historial local guarda copias).
  ```
  [personal | hex@gmail.com]
  Gmail=mi contraseña
  Spotify=otra

  [trabajo | hex@empresa.com]
  Slack=abc123
  ```

`copy`, `get`, `edit`, `set`, `rm` y `mv` no necesitan el nombre exacto: primero buscan el nombre tal cual, después sin distinguir mayúsculas ni acentos, y al final cualquier entrada que lo contenga (`sulfur copy gmail` encuentra "Gmail personal"). Si hay varias coincidencias, piden elegir por número. `add` y `gen` siempre usan el nombre exacto, porque un nombre nuevo crea una entrada.

La bóveda vive en `%APPDATA%\sulfur\vault.json` en Windows (el directorio de datos del usuario en otros sistemas). La variable de entorno `SULFUR_VAULT` apunta a otra ruta.

## Features

- Huella determinista en OKLCH: el texto se normaliza a NFC, la luminosidad se mantiene entre 0.45 y 0.85 (nunca negro ni blanco puros) y el croma se recorta lo justo para caber en sRGB.
- Argon2id con los parámetros recomendados por RFC 9106 (3 pasadas, 64 MiB, 4 carriles), guardados en el archivo y acotados al leerlo.
- XChaCha20-Poly1305 por entrada: cualquier byte alterado se detecta y una entrada no puede moverse ni hacerse pasar por otra.
- Índice sellado: borrar, reordenar o reinsertar entradas viejas en el archivo se detecta.
- Relleno a bloques de 256 bytes: en disco, todas las entradas comunes miden lo mismo.
- Categoría y correo o usuario por entrada, cifrados junto con el secreto.
- Generador de contraseñas sin sesgo de módulo, con al menos un carácter de cada clase.
- Guardado atómico: un corte a medio guardar no deja la bóveda truncada.
- Contraseñas leídas sin eco y sin historial; Unicode correcto en la consola de Windows.
- Pruebas de propiedades con QuickCheck sobre la huella y la bóveda.

## Future Features

- Huella como imagen PNG.
- Interfaz web, si se decide.

## Autoría

por Hex ([@RemiH06](https://github.com/RemiH06))
