# Ejemplo de archivo para sulfur import
# Toda línea que empieza con # se ignora, igual que las vacías.
# Una entrada por línea: nombre=secreto, partida en el primer =.
# El nombre puede llevar espacios; el secreto se toma literal (puede llevar = o #).
# Un encabezado [categoría | usuario] aplica a todo lo de abajo hasta el siguiente.
# Nada de viñetas (- o *), tablas ni comillas alrededor del secreto.

[correo | remi@example.com]
Proton=k7#Qm2vX9pL4wR8z
Correo viejo=Tq3=nB6yH1jF5sD0

# Solo categoría: sin usuario
[bancos]
Banco Ejemplo=Wm4!rT8kZ2qN6vP1

# Solo usuario: sin categoría
[| hex]
Debian=pA9xC3mV7bN1qL5k
Pixilate=Rz6&tY2uJ8wE4oI0

# La categoría se guarda en minúsculas: Juegos queda como juegos
[Juegos | remi.ejemplo]
Minecraft=Xs5^dF1gH7jK3lQ9

# [] quita categoría y usuario para lo que sigue
[]
Wifi casa=contraseña con espacios y ñ
