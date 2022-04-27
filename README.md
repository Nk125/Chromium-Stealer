# Chromium-Stealer

Stealea contraseñas de chromium, se compila con sqlite3, programado en C++

## SQLite 3
Puedes compilar [sqlite3.c](https://www.sqlite.org/download.html) a un .obj y convertirlo a .lib para que sea compatible con el programa
o en cambio puedes simplemente añadir sqlite3.c al comando de compilación junto con el stealer y remover el pragma que lo importa.

**Recomiendo la instalación amalgamate**

```bat
cl [...] sqlite3.c -c
lib /out:sqlite3.lib sqlite3.obj
cl [...] main.cpp
:: O también
cl [...] sqlite3.c main.cpp
```

## Otras dependencias:
[nlohmann:JSON.hpp](https://github.com/nlohmann/json/blob/develop/single_include/nlohmann/json.hpp)
[tomykaira:Base64.h](https://gist.github.com/tomykaira/f0fd86b6c73063283afe550bc5d77594)
[PlusAES Wrapper](https://github.com/Nk125/PlusAes-Wrapper)
[Simple Binary File Handler](https://github.com/Nk125/CPP-LocalProjects/tree/main/Simple%20Binary%20File%20Handler)
