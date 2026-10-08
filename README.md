# Seguridad en WordPress con presupuesto cero

Recursos de la charla de Fernando Tellado en el **Meetup WordPress Coruña 2026**.

**La presentación, en PDF:** [`seguridad-wordpress-presupuesto-cero.pdf`](seguridad-wordpress-presupuesto-cero.pdf).

Todo lo que se enseñé en pantalla está aquí, con el mismo orden de la charla y en tres actos: primero lo que WordPress ya hace bien y solo pide que lo mires (ajustes del escritorio, sin plugins ni nada), después lo que hace mal o le falta y cómo se arregla, de menos a más código (`wp-config.php`, `.htaccess` y un archivo PHP) y, al final, Vigilante para comprobarlo todo.

Una norma para todo lo que viene: **cada capa cuesta 0 €, y ninguna sustituye a las tres que de verdad protegen**. Actualizar, contraseñas largas y únicas e identificación en dos pasos. Lo de esta carpeta es capa extra, no un escudo.

> Antes de tocar `wp-config.php`, `.htaccess` o subir un archivo a `mu-plugins`, haz una copia de seguridad. Siempre. Y si puedes, pruébalo antes en una copia de la web.

## Archivos de esta carpeta

| Archivo | Qué es | Diapositiva |
|---|---|---|
| [`seguridad-wordpress-presupuesto-cero.pdf`](seguridad-wordpress-presupuesto-cero.pdf) | La presentación de la charla, completa | 1 a 45 |
| [`wp-config-fragmentos.php`](wp-config-fragmentos.php) | Las líneas para quitar el editor de código, forzar https en el escritorio, apagar la depuración y limitar el HTML sin filtrar, más dos opcionales con su contrapeso | 22 y 23 |
| [`uploads.htaccess`](uploads.htaccess) | PHP fuera de la carpeta de subidas | 25 |
| [`htaccess-raiz.htaccess`](htaccess-raiz.htaccess) | Limpieza en la raíz: sin listado de carpetas, sin `readme.html`, sin `.log`, `.sql` ni `.bak` descargables y `xmlrpc.php` cortado | 26 |
| [`ayudawp-hardening.php`](ayudawp-hardening.php) | mu-plugin de un solo archivo con el refuerzo de acceso, usuarios, cabeceras y vigilancia | 28 a 36 |

---

## 1. Acto 1: lo que WordPress ya hace bien · diapositivas 3 a 18

Sin plugins ni código. Cinco pantallas del escritorio que, bien ajustadas, son seguridad:

| Pantalla | Qué mirar | Diapositivas |
|---|---|---|
| **Herramientas › Salud del sitio** | Avisa de PHP sin soporte, plugins sin usar, depuración encendida o falta de https, y cada aviso explica cómo arreglarlo. Revisa configuración: no busca malware | 6 |
| **Escritorio › Actualizaciones** y **Plugins** | Actualizar es lo más eficaz que hay. Reinstalar el núcleo da una copia limpia sin tocar tu contenido. Borra los plugins y temas inactivos. Las actualizaciones automáticas se activan plugin a plugin y tema a tema, y si una falla con error fatal, WordPress la revierte | 8 y 9 |
| **Ajustes › Generales** | Las dos direcciones con https. Registro abierto desactivado y, si lo necesitas, con rol Suscriptor. Un correo de administración que leas | 11 |
| **Usuarios › Perfil** y **Todos los usuarios** | El nombre público no debe ser el de acceso. El botón para cerrar sesión en todos los demás sitios. Las contraseñas de aplicación, con su último uso e IP. Menos administradores: quien escribe es autor o editor | 13 y 14 |
| **Ajustes › Comentarios** y **Ajustes › Escritura** | Pingbacks y trackbacks fuera (primera línea contra los abusos de XML-RPC), servicios de actualización vacíos, aprobación manual y cola para comentarios con dos o más enlaces | 16 a 18 |

Dos detalles de la diapositiva 17: las casillas de pings solo afectan a las entradas nuevas, y para las ya publicadas hay que usar la edición en bloque (**Seleccionar › Acciones › Editar › Pings: No permitir**). Y cerrar los pingbacks no cierra todo XML-RPC.

Y un contrapeso que conviene tener presente: disuadir a los buscadores es una petición educada, no un muro; cambiar la URL de acceso o el prefijo de las tablas quita ruido de bots y poco más, y ocultar la versión no te hace invulnerable. Capa extra, nunca en lugar de actualizar.

---

## 2. Acto 2: lo que falla y dónde se arregla · diapositivas 19 a 38

Se recorre de menos a más código. Con cada paso se ve qué falla y en qué archivo se arregla.

### `wp-config.php` · diapositivas 22 y 23

Las líneas están en [`wp-config-fragmentos.php`](wp-config-fragmentos.php). Copia solo las que necesites y, si alguna ya existe en tu archivo (`WP_DEBUG` casi seguro), cambia la que hay en vez de añadir otra.

- `DISALLOW_FILE_EDIT`: quita el editor de archivos de temas y plugins. Desde ahí se puede escribir PHP en tu servidor sin subir nada.
- `FORCE_SSL_ADMIN`: escritorio y acceso siempre por https. Solo si tu web ya funciona entera con https.
- `WP_DEBUG` en `false`: la depuración, apagada en producción.
- `DISALLOW_UNFILTERED_HTML`: ni los administradores publican HTML sin filtrar. Con el contrapeso de que tampoco podrán pegar scripts o iframes en un bloque de HTML personalizado.
- Opcionales y comentadas: `DISALLOW_FILE_MODS` (bloquea instalar y actualizar desde el escritorio, **y también las actualizaciones automáticas**) y `DISABLE_WP_CRON` (solo con un cron real creado antes).
- Claves y sales nuevas, para después de cualquier susto: <https://api.wordpress.org/secret-key/1.1/salt/>. Al cambiarlas se cierra la sesión de todo el mundo, tú incluido.

Dos cosas que no son código: el `wp-config.php` puede vivir una carpeta por encima de la raíz web, y sus permisos conviene dejarlos en 440 o 400.

### `.htaccess` · diapositivas 25 y 26

Para Apache y LiteSpeed. En Nginx son reglas equivalentes en la configuración del servidor; pídeselas a tu hosting.

- [`uploads.htaccess`](uploads.htaccess) va **dentro** de `wp-content/uploads/` con el nombre `.htaccess`. Aunque alguien consiga subir un `.php` disfrazado de imagen, el servidor no lo ejecuta.
- [`htaccess-raiz.htaccess`](htaccess-raiz.htaccess) va en el `.htaccess` de la raíz, **fuera** del bloque «BEGIN WordPress ... END WordPress». Si al ponerlo la web da error 500, casi seguro es la línea `Options -Indexes`: tu hosting no deja cambiar esa opción desde el `.htaccess`. Quítala y pídeselo a tu hosting.
- La regla de `xmlrpc.php` es solo para quien no use la app móvil de WordPress ni Jetpack.

Las reglas están probadas en Apache 2.4: lo que debe dar 403 lo da (PHP en subidas en todas sus extensiones, `readme.html`, `license.txt`, `wp-config.php`, `.log`, `.sql`, `.bak`, `xmlrpc.php` y el listado de carpetas), y imágenes, PDF y el resto de la web siguen respondiendo con normalidad. Un efecto lateral: la regla de `readme.html` y `license.txt` también bloquea los de los plugins, que a nadie le hacen falta por URL.

### El archivo PHP · diapositivas 28 a 36

[`ayudawp-hardening.php`](ayudawp-hardening.php) es un mu-plugin: súbelo a `wp-content/mu-plugins/` (crea la carpeta si no existe) y se carga solo, sin activarlo. Es un único archivo, con comentarios en español, que puedes leer entero en diez minutos antes de ponerlo.

| Bloque | Qué hace | Diapositiva |
|---|---|---|
| Acceso: límite de intentos | Tras 5 fallos desde la misma IP, no deja entrar hasta que pasen 15 minutos desde el primero, **incluso con la contraseña correcta** | 29 |
| Acceso: el mismo error y sesiones más cortas | El formulario de acceso da el mismo mensaje exista o no el usuario. Sesión de 12 horas, o 3 días con «Recuérdame» (en vez de 2 y 14) | 30 |
| Acceso: XML-RPC, pings y contraseñas de aplicación | XML-RPC cerrado, pings cerrados en todas las entradas y contraseñas de aplicación apagadas | 31 |
| Usuarios: `?author=` y API REST | `/?author=1` redirige a la portada y la API REST deja de listar usuarios a quien no ha iniciado sesión | 32 |
| Usuarios: mapa del sitio, nombres y aviso | Fuera los usuarios del mapa del sitio, nombres reservados (`admin`, `root`...) y un correo al administrador cuando alguien recibe el rol de administrador | 33 |
| Cabeceras de seguridad | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` y HSTS si la petición es https | 34 y 35 |
| Vigilar y limpiar | Cada día busca archivos PHP en la carpeta de subidas y avisa por correo si los hay. Quita la versión de WordPress del código de la página | 36 |

**Cambiar los valores sin tocar el archivo.** Todos están en la función `ayudawp_settings()` y se pueden cambiar con un filtro desde otro mu-plugin. Por ejemplo, si usas Jetpack o la app móvil y quieres el límite en 3 intentos:

```php
<?php
// wp-content/mu-plugins/ayudawp-hardening-ajustes.php
add_filter( 'ayudawp_settings', function ( $settings ) {
	$settings['max_attempts']          = 3;
	$settings['xmlrpc']                = 'no_pingbacks'; // 'off', 'no_pingbacks' u 'on'
	$settings['application_passwords'] = true;
	return $settings;
} );
```

Los demás ajustes son `lock_minutes`, `session_hours`, `session_remember_days`, `close_pings`, `reserved_usernames`, `hsts_seconds` (0 para no enviar HSTS) y `strip_core_version`. Con `max_attempts` en 0, el límite de intentos se desactiva.

**Probado.** El archivo se ha probado en un WordPress 7.1.3 con PHP 8.4 (límite de intentos, mensaje genérico, duración de las sesiones, XML-RPC, usuarios y mapa del sitio, aviso de administrador, escaneo y cabeceras), con la depuración activa y sin un solo aviso de PHP. Aun así, pruébalo en tu web antes de ponerlo en producción: cada tema, plugin y hosting es un mundo.

**Contrapesos que conviene leer antes de ponerlo:**

- **La IP.** El límite de intentos usa `REMOTE_ADDR` y nada más, porque cabeceras como `X-Forwarded-For` las escribe quien hace la petición y cualquiera puede inventarlas. Si tu web está detrás de Cloudflare o de otro proxy, el servidor tiene que restaurar la IP real del visitante en `REMOTE_ADDR` (tu hosting lo sabrá). Si no, todos los visitantes parecen la misma IP y cinco fallos de cualquiera bloquean a todos. Para comprobarlo: sube un archivo suelto con `<?php echo $_SERVER['REMOTE_ADDR'];`, ábrelo desde el móvil con datos, compara con la IP que te dé un buscador de «mi IP» y **bórralo** al terminar. Si no coinciden, pon `max_attempts` en 0 hasta que lo arregles.
- **Recuperar contraseña.** El formulario de «¿Has olvidado tu contraseña?» del núcleo sigue diciendo si la cuenta existe, y este archivo no lo toca.
- **Contraseñas de aplicación apagadas.** Si usas la app móvil, Zapier, un cliente de la API REST o cualquier integración que se autentique así, ponlas en `true`.
- **API REST sin usuarios.** Si un tema o una aplicación lee la lista de usuarios sin sesión, deja de funcionar. Mira la web después de activarlo.
- **Nombres reservados.** Solo se reservan los que nadie usa todavía (el núcleo aplica la lista también al editar usuarios, y un usuario existente llamado `admin` tiene que poder guardar su perfil). Si registras clientes de WooCommerce con el nombre sacado del correo, quien tenga `admin@` no podrá crear la cuenta.
- **Correo.** El aviso de administrador nuevo y el del escaneo salen con `wp_mail()`. Si tu web no envía correos de forma fiable, no te enterarás; compruébalo con un plugin de SMTP.
- **Cabeceras.** Si tu caché de página la sirve el servidor sin pasar por PHP, no se envían; ponlas entonces en el `.htaccess` o en una regla de Cloudflare. `Content-Security-Policy` se queda fuera a propósito, porque una política mal puesta rompe el editor de bloques y muchos plugins en dos minutos. Antes de activar HSTS, asegúrate de que el https funciona en todo el dominio.
- **Escaneo diario.** Usa WP-Cron, así que si apagas `DISABLE_WP_CRON` sin un cron real, no corre. Avisa pero no borra nada, y solo manda correo cuando la lista cambia. Algunos plugins (cachés, copias, constructores de formularios) guardan PHP en las subidas de forma legítima: el aviso te dirá cuáles y decides tú.
- **Quitar la versión.** Sin `?ver=`, el navegador no sabe que un archivo del núcleo ha cambiado. Con una caché del navegador larga, tras actualizar WordPress puede tardar en coger los archivos nuevos. Si lo notas, pon `strip_core_version` en `false`.

**Si algún día lo quitas:** borra el archivo y listo. Quedan en la base de datos el evento diario `ayudawp_daily_scan` (se ve y se borra con [WP Crontrol](https://wordpress.org/plugins/wp-crontrol/)) y la opción `ayudawp_last_scan`, que no hacen nada.

### Lo que no se arregla con cuatro funciones · diapositiva 38

El archivo **no** hace: un segundo factor de verdad (códigos TOTP, lectura de QR y dispositivos de confianza), una URL de acceso propia (con su regla de reescritura y sus excepciones) ni un cortafuegos con reglas (los patrones caseros dan falsos positivos y no se actualizan solos). Eso es mucho más código del que cabe en un archivo, y ahí entra el tercer acto.

---

## 3. Acto 3: Vigilante, para comprobarlo todo · diapositivas 39 a 44

[Vigilante](https://es.wordpress.org/plugins/vigilante/) es un plugin mío, gratuito y sin versión de pago. No se usó para hacer el trabajo del acto 2, sino para **comprobarlo**: lo que hemos puesto a mano, ¿se ve desde fuera?

- **La Comprobación de seguridad** (diapositivas 41 a 43). Más de 50 comprobaciones en 6 categorías (SSL/TLS, cabeceras HTTP, exposición de WordPress, acceso e identificación, archivos sensibles y comprobaciones internas). Corre en tu servidor, sin cuentas ni claves de ningún servicio.
- **La nota** (diapositiva 42). De 0 a 100 y con calificación de A a E. En verde, lo que ve en el sitio en vivo; en rojo, lo que falta o lo que el plugin no puede ver.
- **Del fallo a la casilla** (diapositiva 43). Cada fallo lleva directo a la casilla que lo arregla.
- **Dos preajustes** (diapositiva 40): Estándar y Máxima seguridad.
- **Antes de activarlo.** Al activarlo aplica sus valores por defecto con todos los módulos encendidos y escribe bloques propios en el `.htaccess` y constantes en `wp-config.php` (si ya tenías definida alguna, como `DISALLOW_FILE_EDIT`, comenta tu línea y pone el valor de sus ajustes; al desactivarlo, quita lo suyo y te devuelve las tuyas). **No guarda copia de esos dos archivos**, porque llevan la contraseña de la base de datos: descárgala tú antes desde su sección de ajustes y herramientas.
- **Cada cosa, una sola vez.** Vigilante y el archivo del acto 2 se pisan en varias cosas (cabeceras, límite de intentos, XML-RPC, usuarios). Si usas Vigilante para esas, no actives también el mu-plugin; si prefieres el mu-plugin, apaga los módulos equivalentes de Vigilante y úsalo solo para comprobar.
- **Lo que el código del acto 2 no alcanza** (diapositiva 44): identificación en dos pasos (aplicación o correo, con códigos de recuperación), URL de acceso propia, cortafuegos y modo Bajo ataque (con reglas, listas de IP y una emergencia que se apaga a las 4 horas), vigilancia de archivos del núcleo, plugins, temas y subidas con aviso por correo, y auditoría con alertas.

---

## Nada de esto cuesta ni un euro · diapositiva 45

| | |
|---|---|
| **Primero** | Ajustes del escritorio, que ya están en tu WordPress |
| **Segundo** | `wp-config.php` y `.htaccess`, una línea o una regla cada vez |
| **Tercero** | Un archivo PHP que puedes leer entero |
| **Y para comprobarlo** | Vigilante |
| **Precio** | 0,00 €, IVA incluido |

¡De nada!

---

## Licencia

El código de esta carpeta se publica bajo licencia GPLv2 o posterior, la misma de WordPress. Úsalo, cámbialo y compártelo.

## Más

- [Ayuda WordPress](https://ayudawp.com): tutoriales y documentación.
- [Servicios de AyudaWP](https://servicios.ayudawp.com): si prefieres que te lo hagamos nosotros.
- [Canal de YouTube](https://www.youtube.com/AyudaWordPressES).
