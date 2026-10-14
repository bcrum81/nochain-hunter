<?php
/**
 * Plugin Name: nochain guard
 * Description: Refuses to load or activate plugins shaped like the nochain / EtherHiding dropper, and blocks WordPress HTTP calls to blockchain RPC endpoints. Companion to nochain-scan.sh.
 *
 * Install as wp-content/mu-plugins/000-nochain-guard.php. The 000- prefix
 * makes it load before any other must-use plugin; nochain-scan.sh knows this
 * exact path and will not flag it.
 *
 * This is a tripwire, not a wall. Anything already executing on the site, or
 * anyone holding your SFTP/SSH/hosting credentials, can edit or delete this
 * file. It stops the known reinstall shapes from loading and tells you when
 * they come back.
 */

defined( 'ABSPATH' ) || exit;

// Hosts the payload fetches from. Kept in step with nochain-scan.sh.
const NOCHAIN_GUARD_RPC_HOSTS = array(
	'mainnet.base.org',
	'base.publicnode.com',
	'base.drpc.org',
	'1rpc.io',
	'blastapi.io',
	'gateway.tenderly.co',
);

$GLOBALS['nochain_guard_blocked'] = array();

/**
 * True if a plugin path ("dir/file.php" or "file.php") matches the dropper's
 * naming conventions. Same rules as nochain-scan.sh.
 */
function nochain_guard_is_suspect( $plugin ) {
	$plugin = strtolower( (string) $plugin );
	$slug   = false !== strpos( $plugin, '/' ) ? strstr( $plugin, '/', true ) : basename( $plugin, '.php' );

	if ( preg_match( '/^(nochain|nc[-_]dropin)/', $slug ) ) {
		return true;
	}

	// <name>-<unix timestamp>, only if the timestamp is a plausible recent date.
	if ( preg_match( '/[-_.](1\d{9})$/', $slug, $m ) ) {
		$ts = (int) $m[1];
		if ( $ts >= 1672531200 && $ts <= time() + YEAR_IN_SECONDS ) {
			return true;
		}
	}

	// <word>-<hex> ("Query Monitor Companion" ships as site-helper-<hex>). The
	// tail must hold a digit and an a-f letter, so words like "facade" pass.
	if ( preg_match( '/^[a-z]+(?:-[a-z]+)*-([0-9a-f]{6,})$/', $slug, $m )
		&& preg_match( '/\d/', $m[1] ) && preg_match( '/[a-f]/', $m[1] ) ) {
		return true;
	}

	return false;
}

function nochain_guard_note( $what ) {
	$GLOBALS['nochain_guard_blocked'][ $what ] = true;
}

// active_plugins is a list of plugin files.
function nochain_guard_strip_list( $plugins ) {
	if ( ! is_array( $plugins ) ) {
		return $plugins;
	}
	foreach ( $plugins as $i => $file ) {
		if ( nochain_guard_is_suspect( $file ) ) {
			nochain_guard_note( $file );
			unset( $plugins[ $i ] );
		}
	}
	return array_values( $plugins );
}

// active_sitewide_plugins (multisite) is keyed by plugin file.
function nochain_guard_strip_keyed( $plugins ) {
	if ( ! is_array( $plugins ) ) {
		return $plugins;
	}
	foreach ( array_keys( $plugins ) as $file ) {
		if ( nochain_guard_is_suspect( $file ) ) {
			nochain_guard_note( $file );
			unset( $plugins[ $file ] );
		}
	}
	return $plugins;
}

// Filter on read so a plugin re-added to the database (even by direct SQL)
// never loads, and on write so it can't be saved back.
add_filter( 'option_active_plugins', 'nochain_guard_strip_list', 1 );
add_filter( 'pre_update_option_active_plugins', 'nochain_guard_strip_list', 1 );
add_filter( 'site_option_active_sitewide_plugins', 'nochain_guard_strip_keyed', 1 );
add_filter( 'pre_update_site_option_active_sitewide_plugins', 'nochain_guard_strip_keyed', 1 );

// activate_plugin() includes the plugin file to test it before the option is
// written, so refuse activation requests outright rather than rely on the
// filters above.
add_action( 'load-plugins.php', function () {
	$requested = array_merge(
		(array) wp_unslash( $_REQUEST['checked'] ?? array() ),
		array( wp_unslash( $_REQUEST['plugin'] ?? '' ) )
	);
	foreach ( $requested as $file ) {
		if ( '' !== $file && nochain_guard_is_suspect( $file ) ) {
			nochain_guard_note( $file );
			wp_die( 'Blocked by nochain guard: this plugin matches a known malware naming pattern.', 403 );
		}
	}
} );

add_filter( 'rest_pre_dispatch', function ( $result, $server, $request ) {
	if ( 0 !== strpos( $request->get_route(), '/wp/v2/plugins' ) || 'GET' === $request->get_method() ) {
		return $result;
	}
	foreach ( array( 'plugin', 'slug' ) as $param ) {
		$value = $request->get_param( $param );
		if ( is_string( $value ) && nochain_guard_is_suspect( $value ) ) {
			nochain_guard_note( $value );
			return new WP_Error( 'nochain_guard', 'Blocked by nochain guard.', array( 'status' => 403 ) );
		}
	}
	return $result;
}, 1, 3 );

// Only catches calls made through the WordPress HTTP API; raw curl or
// file_get_contents in a backdoor bypasses this.
add_filter( 'pre_http_request', function ( $pre, $args, $url ) {
	$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
	foreach ( NOCHAIN_GUARD_RPC_HOSTS as $bad ) {
		if ( $host === $bad || substr( $host, -strlen( $bad ) - 1 ) === '.' . $bad ) {
			nochain_guard_note( 'HTTP request to ' . $host );
			return new WP_Error( 'nochain_guard', 'Blocked request to blockchain RPC host ' . $host );
		}
	}
	return $pre;
}, 1, 3 );

add_action( 'admin_notices', function () {
	if ( empty( $GLOBALS['nochain_guard_blocked'] ) || ! current_user_can( 'activate_plugins' ) ) {
		return;
	}
	printf(
		'<div class="notice notice-error"><p><strong>nochain guard</strong> blocked: %s. The files may still be on disk &mdash; run nochain-scan.sh and find how they got back.</p></div>',
		esc_html( implode( ', ', array_keys( $GLOBALS['nochain_guard_blocked'] ) ) )
	);
} );

// Log to the PHP error log, at most once an hour, so a reinfection shows up
// even if nobody opens the dashboard.
add_action( 'shutdown', function () {
	if ( empty( $GLOBALS['nochain_guard_blocked'] ) || get_transient( 'nochain_guard_logged' ) ) {
		return;
	}
	set_transient( 'nochain_guard_logged', 1, HOUR_IN_SECONDS );
	error_log( 'nochain guard blocked: ' . implode( ', ', array_keys( $GLOBALS['nochain_guard_blocked'] ) ) );
} );
