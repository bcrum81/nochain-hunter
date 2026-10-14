<?php
/**
 * Plugin Name: Block user enumeration
 * Description: Stops WordPress from handing an unauthenticated visitor the list of usernames/logins — via the REST users endpoint, the ?author=N redirect, and oEmbed author data. Companion to nochain-scan.sh / 000-nochain-guard.php.
 *
 * Install as wp-content/mu-plugins/001-block-user-enumeration.php. Loads
 * after 000-nochain-guard.php. If your host offers a WAF, a rule blocking
 * /wp-json/wp/v2/users is a lighter-weight alternative; this covers sites
 * without that, and closes the ?author= and oEmbed routes too.
 *
 * A logged-in user who can already list users (administrators) is unaffected,
 * so the dashboard's author dropdowns keep working.
 */

defined( 'ABSPATH' ) || exit;

/**
 * Everyone who is allowed to see the user list. Anyone else is treated as an
 * anonymous visitor for the purposes of the rules below.
 */
function nochain_may_list_users() {
	return is_user_logged_in() && current_user_can( 'list_users' );
}

/**
 * Remove the REST routes that expose users. Covers both request shapes that
 * reach them: /wp-json/wp/v2/users and /?rest_route=/wp/v2/users.
 */
add_filter( 'rest_endpoints', function ( $endpoints ) {
	if ( nochain_may_list_users() ) {
		return $endpoints;
	}
	foreach ( array( '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ) as $route ) {
		unset( $endpoints[ $route ] );
	}
	return $endpoints;
} );

/**
 * Belt and braces: if some other route still tries to return user objects to
 * an anonymous caller, refuse it rather than trust the unset above.
 */
add_filter( 'rest_authentication_errors', function ( $result ) {
	if ( is_wp_error( $result ) || nochain_may_list_users() ) {
		return $result;
	}
	$route = $GLOBALS['wp']->query_vars['rest_route'] ?? ( $_GET['rest_route'] ?? '' );
	if ( is_string( $route ) && preg_match( '#/wp/v2/users#', $route ) ) {
		return new WP_Error( 'nochain_no_user_enum', 'User enumeration is disabled.', array( 'status' => 401 ) );
	}
	return $result;
}, 20 );

/**
 * Block the classic ?author=N probe, which normally 301-redirects to
 * /author/<login>/ and thereby leaks the login name. Runs before that
 * redirect. Only touches front-end requests carrying a numeric author id.
 */
add_action( 'parse_request', function ( $wp ) {
	if ( is_admin() || nochain_may_list_users() ) {
		return;
	}
	$author = $_GET['author'] ?? ( $wp->query_vars['author'] ?? '' );
	if ( '' !== $author && is_numeric( (string) $author ) ) {
		wp_die( 'User enumeration is disabled.', 'Forbidden', array( 'response' => 403 ) );
	}
} );

/**
 * The author archive itself (/author/<login>/) also confirms a login exists.
 * Send anonymous visitors to the home page instead of rendering it.
 */
add_action( 'template_redirect', function () {
	if ( is_author() && ! nochain_may_list_users() ) {
		wp_safe_redirect( home_url( '/' ), 301 );
		exit;
	}
} );

/**
 * oEmbed responses embed the author's name and URL; strip that for anonymous
 * callers so /wp-json/oembed/1.0/embed?url=... can't be used the same way.
 */
add_filter( 'oembed_response_data', function ( $data ) {
	if ( ! nochain_may_list_users() ) {
		unset( $data['author_name'], $data['author_url'] );
	}
	return $data;
}, 20 );
