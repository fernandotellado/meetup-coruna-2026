<?php
/**
 * Fragmentos para wp-config.php
 * Charla «Seguridad en WordPress con presupuesto cero» · Meetup WordPress Coruña 2026
 *
 * Esto NO es un archivo para subir tal cual. Copia las líneas que necesites
 * y pégalas en tu wp-config.php, justo encima de la línea que dice
 * «/* That's all, stop editing! *\/» (o «¡Eso es todo, deja de editar!»
 * si tu instalación está en español).
 *
 * Si alguna de estas constantes ya está en tu wp-config.php (WP_DEBUG casi
 * seguro que sí), cambia la que hay en vez de añadir otra: definir dos veces
 * la misma constante da un aviso de PHP.
 *
 * Antes de tocar wp-config.php, haz una copia del archivo.
 */

/*
 * Diapositivas 22 y 23 · Lo peor que trae WordPress: un editor de código
 * Quita el editor de archivos de temas y plugins del escritorio. Desde ahí se
 * puede escribir PHP en tu servidor sin subir nada. Una línea, y WordPress puro.
 */
define( 'DISALLOW_FILE_EDIT', true );

/*
 * Diapositiva 22 · Escritorio y acceso siempre por HTTPS
 * Úsala solo si tu web ya funciona entera con https (Ajustes › Generales,
 * las dos direcciones). Si no, te quedas sin poder entrar.
 */
define( 'FORCE_SSL_ADMIN', true );

/*
 * Diapositiva 22 · Depuración apagada
 * Con WP_DEBUG en true, los errores de PHP salen en pantalla y cuentan
 * rutas y versiones. Si necesitas depurar en una copia de pruebas, ahí sí.
 */
define( 'WP_DEBUG', false );

/*
 * Diapositiva 22 · Ni los administradores publican HTML sin filtrar
 * Quita la capacidad «unfiltered_html» a todos, administradores incluidos. Si una
 * cuenta de administrador cae, no podrá meter scripts en las entradas.
 *
 * Contrapeso: los administradores también dejan de poder pegar HTML con scripts
 * o iframes en un bloque de HTML personalizado o en un widget. Si lo necesitas
 * para embeber algo, prueba antes y no actives esta línea a ciegas.
 */
define( 'DISALLOW_UNFILTERED_HTML', true );

/*
 * Opcional · Bloquear instalar y actualizar desde el escritorio
 * Cierra la puerta que deja abierta quitar solo el editor: un administrador
 * comprometido todavía puede instalar un plugin malicioso.
 *
 * ¡OJO! También bloquea las actualizaciones automáticas, incluidas las de
 * seguridad, y las manuales desde el escritorio. Solo tiene sentido si
 * despliegas tú, por ejemplo desde Git, y te encargas de actualizar. Por
 * eso va comentada.
 */
// define( 'DISALLOW_FILE_MODS', true );

/*
 * Opcional · Apagar el cron que WordPress dispara con las visitas
 * wp-cron.php es una URL pública que se ejecuta cuando entra una visita, y
 * hay quien la golpea a propósito para cargar el servidor.
 *
 * ¡OJO! Activa esta línea SOLO después de crear un cron real en el panel de
 * tu hosting que llame a wp-cron.php cada 5 o 15 minutos. Si la activas sin
 * cron real, se paran las tareas programadas: entradas programadas,
 * copias de seguridad, actualizaciones automáticas y el escaneo diario del
 * archivo ayudawp-hardening.php. Por eso va comentada.
 */
// define( 'DISABLE_WP_CRON', true );

/*
 * Diapositiva 23 · Después de un susto: claves y sales nuevas
 * Esto no se pega aquí. Entra en https://api.wordpress.org/secret-key/1.1/salt/
 * y copia las ocho líneas que te genera sobre las ocho que ya hay en tu
 * wp-config.php (AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY y sus
 * cuatro SALT). Al cambiarlas se cierra la sesión de todo el mundo, tú incluido.
 */

/*
 * Dos cosas más que no son código
 * - WordPress acepta el wp-config.php una carpeta por encima de la raíz web,
 *   donde ninguna petición llega. Si tu hosting lo permite, muévelo allí.
 * - Los permisos del archivo, mejor en 440 o 400 (lo cambias desde el
 *   administrador de archivos o el FTP de tu hosting). Si WordPress deja de
 *   poder leerlo, sube a 640.
 */
