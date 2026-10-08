<?php
/**
 * Plugin Name:       AyudaWP Hardening
 * Description:       Refuerzo de seguridad en un solo archivo: límite de intentos de acceso, error genérico en el acceso, sesiones más cortas, XML-RPC y pings cerrados, usuarios menos visibles, cabeceras de seguridad, escaneo diario de PHP en las subidas y limpieza de la versión de WordPress.
 * Version:           1.0.0
 * Author:            Fernando Tellado
 * Author URI:        https://ayudawp.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 6.0
 * Requires PHP:      7.4
 *
 * Charla «Seguridad en WordPress con presupuesto cero» · Meetup WordPress Coruña 2026
 *
 * Uso: sube este archivo a wp-content/mu-plugins/ (crea la carpeta si no existe).
 * Pruébalo antes en un entorno de pruebas: un error de sintaxis en un mu-plugin
 * da un error crítico en toda la web. Haz copia de seguridad antes de empezar.
 *
 * Qué hace, por bloques:
 *   1. Acceso: límite de intentos por IP, el mismo error exista o no el usuario,
 *      sesiones más cortas, XML-RPC y pings cerrados, contraseñas de aplicación apagadas.
 *   2. Usuarios: ?author= y API REST sin nombres, mapa del sitio sin usuarios,
 *      nombres reservados y aviso por correo cuando alguien recibe el rol de administrador.
 *   3. Cabeceras de seguridad en la parte pública.
 *   4. Vigilar y limpiar: escaneo diario de archivos PHP en las subidas y fuera la versión
 *      de WordPress del código de la página.
 *
 * Si algún día lo quitas: el evento diario 'ayudawp_daily_scan' y la opción 'ayudawp_last_scan'
 * se quedan en la base de datos sin hacer nada. Los borras con WP Crontrol y con una
 * consulta a la tabla de opciones, o los dejas, que no molestan.
 *
 * Todos los valores están en ayudawp_settings(). Para cambiarlos sin tocar este archivo,
 * usa el filtro 'ayudawp_settings' desde otro mu-plugin.
 *
 * Qué NO hace: segundo factor, URL de acceso propia, cortafuegos con reglas ni auditoría
 * de lo que pasa en el sitio. Para eso hace falta más código del que cabe aquí.
 */

defined( 'ABSPATH' ) || exit;

/* ---------------------------------------------------------------------
 * Ajustes y utilidades
 * ------------------------------------------------------------------ */

/**
 * Valores por defecto de todo el archivo.
 *
 * Se leen siempre en tiempo de ejecución, así que otro mu-plugin que cargue
 * después de este puede cambiarlos con el filtro 'ayudawp_settings'.
 *
 * @return array
 */
function ayudawp_settings() {
	static $settings = null;

	if ( null === $settings ) {
		$defaults = array(
			// Acceso: fallos permitidos por IP y minutos que dura el bloqueo. Con 0 fallos, el límite se desactiva.
			'max_attempts'          => 5,
			'lock_minutes'          => 15,
			// Sesiones: 12 horas, o 3 días con «Recuérdame» (WordPress usa 2 y 14 días).
			'session_hours'         => 12,
			'session_remember_days' => 3,
			// XML-RPC: 'off' (cerrado del todo), 'no_pingbacks' (abierto, sin pingbacks) o 'on'.
			'xmlrpc'                => 'off',
			// Pings cerrados en todas las entradas, las viejas y las nuevas.
			'close_pings'           => true,
			// Contraseñas de aplicación: false las apaga. Déjalas en true si usas apps o integraciones externas.
			'application_passwords' => false,
			// Nombres de usuario que no se pueden registrar.
			'reserved_usernames'    => array( 'admin', 'administrator', 'root', 'test', 'webmaster' ),
			// HSTS: segundos que el navegador recuerda que tu web va por HTTPS. 0 para no enviarlo.
			'hsts_seconds'          => YEAR_IN_SECONDS,
			// Quita ?ver= de los archivos del núcleo (ver el comentario en ayudawp_remove_version_query).
			'strip_core_version'    => true,
		);

		$custom   = apply_filters( 'ayudawp_settings', $defaults );
		$settings = is_array( $custom ) ? array_merge( $defaults, $custom ) : $defaults;
	}

	return $settings;
}

/**
 * Devuelve un ajuste concreto.
 *
 * @param string $key Clave del ajuste.
 * @return mixed
 */
function ayudawp_setting( $key ) {
	$settings = ayudawp_settings();

	return isset( $settings[ $key ] ) ? $settings[ $key ] : null;
}

/**
 * IP del visitante, tal y como la ve el servidor.
 *
 * Usa REMOTE_ADDR y nada más. Las cabeceras X-Forwarded-For o similares las escribe
 * quien hace la petición, así que cualquiera puede inventárselas y saltarse el límite
 * de intentos. Si tu web está detrás de Cloudflare o de un proxy, lo correcto es que
 * el servidor (o tu hosting) restaure la IP real en REMOTE_ADDR; este archivo
 * funcionará sin tocar nada.
 *
 * @return string IP válida, o cadena vacía si no hay forma de saberla.
 */
function ayudawp_client_ip() {
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	$ip = (string) apply_filters( 'ayudawp_client_ip', $ip );

	return false !== rest_is_ip_address( $ip ) ? $ip : '';
}

/* ---------------------------------------------------------------------
 * 1. ACCESO
 * ------------------------------------------------------------------ */

/**
 * Clave del transitorio donde se guardan los fallos de una IP.
 *
 * @param string $ip IP del visitante.
 * @return string
 */
function ayudawp_failed_logins_key( $ip ) {
	return 'ayudawp_fails_' . md5( $ip );
}

/**
 * Cuenta un intento de acceso fallido de esta IP.
 *
 * El plazo se fija con el primer fallo y no se alarga con los siguientes: pasados
 * lock_minutes desde el primero, la cuenta vuelve a cero. Tampoco se borra al
 * entrar bien, porque entonces quien tenga una cuenta propia podría reiniciar
 * el contador entre intento e intento.
 *
 * @param string        $username Usuario o correo con el que se ha intentado entrar.
 * @param WP_Error|null $error    Error del intento fallido (WordPress 5.4 o posterior).
 */
function ayudawp_track_failed_login( $username, $error = null ) {
	// Los intentos rechazados por el propio bloqueo no cuentan.
	if ( $error instanceof WP_Error && 'ayudawp_locked' === $error->get_error_code() ) {
		return;
	}

	$ip = ayudawp_client_ip();
	if ( '' === $ip ) {
		return;
	}

	$key  = ayudawp_failed_logins_key( $ip );
	$data = get_transient( $key );

	if ( ! is_array( $data ) || empty( $data['until'] ) || $data['until'] <= time() ) {
		$data = array(
			'count' => 0,
			'until' => time() + (int) ayudawp_setting( 'lock_minutes' ) * MINUTE_IN_SECONDS,
		);
	}

	++$data['count'];

	set_transient( $key, $data, max( 1, $data['until'] - time() ) );
}
add_action( 'wp_login_failed', 'ayudawp_track_failed_login', 10, 2 );

/**
 * Bloquea el acceso desde una IP que ha superado el límite de intentos.
 *
 * Va con prioridad 99, después de los filtros del núcleo (prioridad 20), a propósito.
 * Si se engancha antes y devuelve un error, wp_authenticate_username_password()
 * comprueba la contraseña igualmente y, si es correcta, devuelve el usuario y borra
 * el error: el bloqueo no serviría justo con el intento que importa.
 *
 * @param WP_User|WP_Error|null $user     Resultado de los filtros anteriores.
 * @param string                $username Usuario o correo.
 * @param string                $password Contraseña.
 * @return WP_User|WP_Error|null
 */
function ayudawp_block_locked_ip( $user, $username, $password ) {
	$username = (string) $username;
	$password = (string) $password;

	// Sin credenciales no hay intento de acceso que bloquear.
	if ( '' === $username && '' === $password ) {
		return $user;
	}

	$max = (int) ayudawp_setting( 'max_attempts' );
	$ip  = ayudawp_client_ip();
	if ( $max < 1 || '' === $ip ) {
		return $user;
	}

	$data = get_transient( ayudawp_failed_logins_key( $ip ) );

	if (
		is_array( $data )
		&& ! empty( $data['until'] )
		&& $data['until'] > time()
		&& (int) $data['count'] >= $max
	) {
		return new WP_Error(
			'ayudawp_locked',
			'<strong>Error:</strong> Demasiados intentos fallidos desde tu conexión. Vuelve a probar dentro de unos minutos.'
		);
	}

	return $user;
}
add_filter( 'authenticate', 'ayudawp_block_locked_ip', 99, 3 );

/**
 * El mismo error de acceso exista o no el usuario.
 *
 * WordPress distingue «usuario no registrado» de «contraseña incorrecta», y eso
 * confirma qué usuarios existen. Aquí solo se cambian esos tres errores; el resto
 * (campos vacíos, enlace de recuperación caducado, bloqueo) se queda como está.
 *
 * @param WP_User|WP_Error|null $user Resultado de los filtros anteriores.
 * @return WP_User|WP_Error|null
 */
function ayudawp_generic_login_error( $user ) {
	if ( ! is_wp_error( $user ) ) {
		return $user;
	}

	$leaky = array( 'invalid_username', 'invalid_email', 'incorrect_password' );

	if ( array_intersect( $leaky, $user->get_error_codes() ) ) {
		// Es el mensaje del propio núcleo, así sale ya traducido.
		return new WP_Error(
			'authentication_failed',
			__( '<strong>Error:</strong> Invalid username, email address or incorrect password.' ) // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- Cadena del propio núcleo, para que salga traducida.
		);
	}

	return $user;
}
add_filter( 'authenticate', 'ayudawp_generic_login_error', 100, 1 );

/**
 * Sesiones más cortas. Solo afecta a los accesos nuevos, no a las sesiones ya abiertas.
 *
 * @param int  $seconds  Duración por defecto en segundos.
 * @param int  $user_id  ID del usuario.
 * @param bool $remember Si marcó «Recuérdame».
 * @return int
 */
function ayudawp_session_length( $seconds, $user_id, $remember ) {
	if ( $remember ) {
		return (int) ayudawp_setting( 'session_remember_days' ) * DAY_IN_SECONDS;
	}

	return (int) ayudawp_setting( 'session_hours' ) * HOUR_IN_SECONDS;
}
add_filter( 'auth_cookie_expiration', 'ayudawp_session_length', 10, 3 );

/**
 * XML-RPC con login cerrado, salvo que el ajuste diga otra cosa.
 *
 * Ojo: este filtro solo corta los métodos que piden usuario y contraseña. Los que
 * no piden login (pingbacks, por ejemplo) siguen vivos; de eso se encarga el filtro
 * de métodos de aquí debajo. Más duro y más barato es cortarlo en el servidor
 * (regla de xmlrpc.php en el .htaccess). Estos filtros sirven si no puedes tocarlo.
 *
 * @param bool $enabled Si XML-RPC está habilitado.
 * @return bool
 */
function ayudawp_xmlrpc_enabled( $enabled ) {
	return 'off' === ayudawp_setting( 'xmlrpc' ) ? false : $enabled;
}
add_filter( 'xmlrpc_enabled', 'ayudawp_xmlrpc_enabled' );

/**
 * Métodos de XML-RPC según el ajuste.
 *
 * 'off': no queda ninguno (solo los system.* que trae el propio servidor, que no hacen nada).
 * 'no_pingbacks': XML-RPC abierto (Jetpack, app móvil) pero sin pingbacks.
 *
 * @param array $methods Métodos disponibles.
 * @return array
 */
function ayudawp_xmlrpc_methods( $methods ) {
	$mode = ayudawp_setting( 'xmlrpc' );

	if ( 'off' === $mode ) {
		return array();
	}

	if ( 'no_pingbacks' === $mode ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
	}

	return $methods;
}
add_filter( 'xmlrpc_methods', 'ayudawp_xmlrpc_methods' );

/**
 * Pings cerrados en todas las entradas, las viejas y las nuevas.
 *
 * @param bool $open Si la entrada acepta pings.
 * @return bool
 */
function ayudawp_pings_open( $open ) {
	return ayudawp_setting( 'close_pings' ) ? false : $open;
}
add_filter( 'pings_open', 'ayudawp_pings_open', 20 );

/**
 * Contraseñas de aplicación apagadas si no usas integraciones externas.
 *
 * @param bool $available Si están disponibles.
 * @return bool
 */
function ayudawp_application_passwords( $available ) {
	return ayudawp_setting( 'application_passwords' ) ? $available : false;
}
add_filter( 'wp_is_application_passwords_available', 'ayudawp_application_passwords' );

/* ---------------------------------------------------------------------
 * 2. USUARIOS
 * ------------------------------------------------------------------ */

/**
 * ?author=1 devuelve el nombre de acceso real aunque el nombre público sea otro.
 * Se manda a la portada. Prioridad 1: antes de la redirección que hace WordPress
 * por su cuenta (redirect_canonical, prioridad 10).
 */
function ayudawp_block_author_scan() {
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Solo se mira si hay un número; no se guarda ni se muestra.
	if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
		wp_safe_redirect( home_url( '/' ), 301 );
		exit;
	}
}
add_action( 'template_redirect', 'ayudawp_block_author_scan', 1 );

/**
 * La API REST deja de listar usuarios a quien no ha iniciado sesión.
 *
 * Si un tema o una aplicación lee la lista de usuarios sin sesión, esto la rompe.
 * Comprueba la web después de activarlo.
 *
 * @param array $endpoints Rutas registradas.
 * @return array
 */
function ayudawp_hide_rest_users( $endpoints ) {
	if ( ! is_user_logged_in() ) {
		unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
	}

	return $endpoints;
}
add_filter( 'rest_endpoints', 'ayudawp_hide_rest_users' );

/**
 * El mapa del sitio de WordPress incluye por defecto wp-sitemap-users-1.xml,
 * con una URL por cada usuario que haya publicado. Aquí se quita.
 *
 * @param WP_Sitemaps_Provider|false $provider Proveedor del mapa.
 * @param string                     $name     Nombre del proveedor.
 * @return WP_Sitemaps_Provider|false
 */
function ayudawp_sitemap_without_users( $provider, $name ) {
	return 'users' === $name ? false : $provider;
}
add_filter( 'wp_sitemaps_add_provider', 'ayudawp_sitemap_without_users', 10, 2 );

/**
 * Nombres de usuario que no se pueden registrar.
 *
 * El núcleo aplica esta lista también al ACTUALIZAR usuarios, no solo al crearlos. Si ya
 * existe un usuario llamado «admin», con «admin» en la lista no podría guardar su perfil
 * ni cambiar su contraseña. Por eso solo se reservan los nombres que nadie usa todavía.
 *
 * Ojo si registras clientes con WooCommerce: si el nombre sale del correo,
 * quien tenga un correo tipo admin@ no podrá crear la cuenta.
 *
 * @param array $logins Nombres ya prohibidos.
 * @return array
 */
function ayudawp_reserved_usernames( $logins ) {
	$reserved = array();

	foreach ( (array) ayudawp_setting( 'reserved_usernames' ) as $name ) {
		if ( is_string( $name ) && '' !== $name && ! username_exists( $name ) ) {
			$reserved[] = $name;
		}
	}

	return array_merge( (array) $logins, $reserved );
}
add_filter( 'illegal_user_logins', 'ayudawp_reserved_usernames' );

/**
 * Correo al administrador del sitio cuando alguien recibe el rol de administrador.
 *
 * El hook add_user_role salta cuando se concede un rol que el usuario no tenía, tanto si
 * se le cambia el rol principal como si se le añade uno más, y también al crear un usuario
 * nuevo. Si ya era administrador, no salta.
 *
 * @param int    $user_id ID del usuario.
 * @param string $role    Rol concedido.
 */
function ayudawp_alert_on_admin_promotion( $user_id, $role ) {
	if ( 'administrator' !== $role || wp_installing() ) {
		return;
	}

	$user = get_userdata( $user_id );
	if ( ! $user ) {
		return;
	}

	$actor = wp_get_current_user();
	$who   = $actor->exists() ? $actor->user_login : 'nadie con sesión iniciada (registro, tarea programada o código)';
	$ip    = ayudawp_client_ip();
	$site  = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

	$subject = sprintf( '[%1$s] Nuevo administrador: %2$s', $site, $user->user_login );
	$subject = trim( (string) preg_replace( '/[\r\n]+/', ' ', $subject ) );

	$message = sprintf(
		"Se ha concedido el rol de administrador a un usuario de %1\$s.\n\nUsuario: %2\$s\nCorreo: %3\$s\nConcedido por: %4\$s\nDirección IP: %5\$s\nFecha: %6\$s\n\nRevisar el usuario: %7\$s\n\nSi no has sido tú ni nadie de tu equipo, cambia las contraseñas de los administradores, revisa la lista de usuarios y renueva las claves y sales de wp-config.php.",
		$site,
		$user->user_login,
		$user->user_email,
		$who,
		'' !== $ip ? $ip : 'desconocida',
		wp_date( 'Y-m-d H:i:s T' ),
		admin_url( 'user-edit.php?user_id=' . (int) $user_id )
	);

	wp_mail( get_option( 'admin_email' ), $subject, $message );
}
add_action( 'add_user_role', 'ayudawp_alert_on_admin_promotion', 10, 2 );

/* ---------------------------------------------------------------------
 * 3. CABECERAS DE SEGURIDAD
 * ------------------------------------------------------------------ */

/**
 * Cabeceras de seguridad en la parte pública.
 *
 * Content-Security-Policy se queda fuera a propósito: una política mal puesta rompe
 * el editor de bloques y muchos plugins en dos minutos. Si tu caché de página la sirve
 * el servidor sin pasar por PHP, estas cabeceras no se envían; en ese caso ponlas en
 * el .htaccess, en la configuración del servidor o en una regla de Cloudflare.
 */
function ayudawp_security_headers() {
	header( 'X-Content-Type-Options: nosniff' );
	header( 'X-Frame-Options: SAMEORIGIN' );
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );
	header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );

	// HSTS: el navegador se acuerda durante ese tiempo. Asegúrate de que el HTTPS funciona
	// en todo el dominio antes de activarlo y, si añadieras includeSubDomains, en todos los subdominios.
	$hsts = (int) ayudawp_setting( 'hsts_seconds' );
	if ( $hsts > 0 && is_ssl() ) {
		header( 'Strict-Transport-Security: max-age=' . $hsts );
	}
}
add_action( 'send_headers', 'ayudawp_security_headers' );

/* ---------------------------------------------------------------------
 * 4. VIGILAR Y LIMPIAR
 * ------------------------------------------------------------------ */

/**
 * Programa el escaneo diario si no estaba programado.
 */
function ayudawp_schedule_scan() {
	if ( wp_installing() ) {
		return;
	}

	if ( ! wp_next_scheduled( 'ayudawp_daily_scan' ) ) {
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'ayudawp_daily_scan' );
	}
}
add_action( 'init', 'ayudawp_schedule_scan' );

/**
 * ¿Es el típico index.php vacío de «Silence is golden»? Esos no se avisan.
 *
 * @param string $path Ruta del archivo.
 * @return bool
 */
function ayudawp_is_silence_stub( $path ) {
	if ( 'index.php' !== strtolower( basename( $path ) ) || filesize( $path ) > 200 ) {
		return false;
	}

	$content = file_get_contents( $path );

	return is_string( $content )
		&& 1 === preg_match( '#^<\?php\s*(//|/\*)\s*Silence is golden\.?\s*(\*/)?\s*(\?>)?\s*$#i', $content );
}

/**
 * Busca archivos PHP dentro de la carpeta de subidas, donde no debería haber ninguno,
 * y avisa por correo al administrador. Solo avisa cuando la lista cambia, para no
 * mandar el mismo correo todos los días.
 *
 * En sitios con cientos de miles de archivos en subidas, el recorrido tiene un tope
 * de 20 segundos y de 100 resultados.
 */
function ayudawp_scan_uploads_for_php() {
	$uploads = wp_get_upload_dir();
	$base    = isset( $uploads['basedir'] ) ? (string) $uploads['basedir'] : '';

	if ( '' === $base || ! is_dir( $base ) ) {
		return;
	}

	$found     = array();
	$truncated = false;
	$start     = microtime( true );

	try {
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::LEAVES_ONLY,
			RecursiveIteratorIterator::CATCH_GET_CHILD
		);

		foreach ( $iterator as $file ) {
			if ( microtime( true ) - $start > 20 ) {
				$truncated = true;
				break;
			}

			if ( ! $file->isFile() || ! preg_match( '/\.(php[0-9]*|phtml|phar|pht)$/i', $file->getFilename() ) ) {
				continue;
			}

			if ( ayudawp_is_silence_stub( $file->getPathname() ) ) {
				continue;
			}

			$found[] = ltrim( substr( $file->getPathname(), strlen( $base ) ), '/\\' );

			if ( count( $found ) >= 100 ) {
				$truncated = true;
				break;
			}
		}
	} catch ( Exception $e ) {
		return;
	}

	if ( empty( $found ) ) {
		// Limpio: si más adelante aparece algo, se vuelve a avisar.
		delete_option( 'ayudawp_last_scan' );
		return;
	}

	sort( $found );
	$hash = md5( implode( "\n", $found ) );

	if ( get_option( 'ayudawp_last_scan' ) === $hash ) {
		return;
	}

	update_option( 'ayudawp_last_scan', $hash, false );

	// Los nombres de archivo pueden llevar caracteres de control: se sustituyen para el correo.
	$list = implode( "\n", array_map( 'ayudawp_clean_path_for_mail', $found ) );
	$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

	$subject = trim( (string) preg_replace( '/[\r\n]+/', ' ', sprintf( '[%s] Archivos PHP en la carpeta de subidas', $site ) ) );

	$message = sprintf(
		"El escaneo diario ha encontrado archivos con extensión de PHP dentro de la carpeta de subidas de %1\$s, donde no debería haber ninguno:\n\n%2\$s\n\n%3\$sNo los abras en el navegador. Mira su contenido desde el servidor (FTP o el administrador de archivos de tu hosting) y, si no los reconoces, bórralos, cambia las contraseñas y renueva las claves y sales de wp-config.php.",
		$site,
		$list,
		$truncated ? "(La lista está recortada: hay más archivos o el escaneo se ha cortado por tiempo.)\n\n" : ''
	);

	wp_mail( get_option( 'admin_email' ), $subject, $message );
}
add_action( 'ayudawp_daily_scan', 'ayudawp_scan_uploads_for_php' );

/**
 * Cambia los caracteres de control de una ruta por «?».
 *
 * @param string $path Ruta relativa.
 * @return string
 */
function ayudawp_clean_path_for_mail( $path ) {
	return (string) preg_replace( '/[\x00-\x1F\x7F]/', '?', $path );
}

/*
 * Limpieza de versión: la etiqueta generator, el enlace RSD y el ?ver= de los archivos
 * del núcleo. Es una capa extra, no un escudo: no te hace invulnerable, solo evita
 * regalar la versión a quien mira qué fallos conocidos probar.
 *
 * Contrapeso: sin ?ver=, el navegador no sabe que un archivo del núcleo ha cambiado. Con
 * una caché del navegador larga, tras actualizar WordPress puede tardar en coger los
 * archivos nuevos. Si lo notas, pon 'strip_core_version' en false.
 */
remove_action( 'wp_head', 'wp_generator' );
remove_action( 'wp_head', 'rsd_link' );
add_filter( 'the_generator', '__return_empty_string' );

/**
 * Quita ?ver= solo cuando coincide con la versión de WordPress. Los plugins y
 * temas conservan el suyo, que es lo que invalida la caché cuando se actualizan.
 *
 * @param string $src URL del archivo.
 * @return string
 */
function ayudawp_remove_version_query( $src ) {
	if ( ! ayudawp_setting( 'strip_core_version' ) || ! is_string( $src ) || false === strpos( $src, 'ver=' ) ) {
		return $src;
	}

	$args = array();
	parse_str( (string) wp_parse_url( $src, PHP_URL_QUERY ), $args );

	if ( isset( $args['ver'] ) && get_bloginfo( 'version' ) === $args['ver'] ) {
		return remove_query_arg( 'ver', $src );
	}

	return $src;
}
add_filter( 'style_loader_src', 'ayudawp_remove_version_query', 9999 );
add_filter( 'script_loader_src', 'ayudawp_remove_version_query', 9999 );
