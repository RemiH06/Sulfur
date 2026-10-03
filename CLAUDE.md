# Sulfur

Convierte texto en colores e imágenes de forma determinista: mismo texto, mismo resultado. Nombre fijo. Objetivo a futuro: que funcione como gestor de contraseñas.

## Estado

- `legacy/kotlin/Sulfur.kt` es la versión 1.0 en Kotlin, un experimento sin valor de seguridad. No se extiende. Sirve solo como referencia de lo que ya existe.
- En marcha: rework completo en **Haskell**, mismo concepto (texto a color/imagen), sin la matemática de Euler ni Fibonacci.

## Dos capas que nunca se mezclan

1. **Huella visual (pública).** Color o imagen derivados de un texto. No es secreta y no protege nada. Sirve para reconocer entradas de un vistazo. Puede ser un degradado, un sólido o un patrón.
2. **Bóveda (secreta).** Cifrado real: clave derivada de la contraseña maestra con Argon2id o scrypt (sal aleatoria), y cifrado autenticado (XChaCha20-Poly1305 o secretbox de libsodium) con nonce aleatorio por cada entrada.

Reglas de seguridad:
- Nunca implementar criptografía propia. Usar bibliotecas revisadas.
- Nunca guardar la maestra ni el texto plano en disco, logs ni salida.
- La huella visual no se deriva de la clave ni de la maestra, solo del nombre de la entrada, para que no sea un canal de filtración.
- Revisión externa antes de usarlo con contraseñas reales.

## Principios (skills globales)

- Filtro `ponytail` antes de cada dependencia o función nueva: ¿stdlib?, ¿ya instalada?, ¿una línea? Sin recortar validación, errores, seguridad ni accesibilidad.
- Colores: `colorimetria` para paletas y contraste WCAG. Nada de `#000` ni `#fff` puros.
- UI con íconos y sin texto de respaldo (si hay interfaz).
- Redacción en español mexicano, sin guión largo (`redaccion-espanol-mx`).
- Commits de una línea, conventional (`commit-checkpoints`). No commitear sin pedirlo.

## Plan Haskell (por confirmar)

- Núcleo puro: texto a hash (SHA-256 de la librería estándar o cripto), hash a color OKLCH, hash a imagen (PNG vía JuicyPixels).
- Pruebas con QuickCheck: determinismo, rango válido, contraste mínimo.
- Criptografía con libsodium (`saltine`) o `crypton`, verificar disponibilidad en Hackage antes de usar.
- CLI primero. Interfaz web después, si se decide.

## Decisiones pendientes

- Formato de salida de la imagen: tamaño, cuadrícula, degradado o sólido por zona.
- Almacenamiento de la bóveda: archivo JSON cifrado o SQLite.
- Si la huella visual se muestra en la bóveda de Obsidian o solo en el CLI.
