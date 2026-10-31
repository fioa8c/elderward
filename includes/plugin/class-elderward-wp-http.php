<?php
/**
 * Engine HTTP adapter built on the WordPress HTTP API.
 *
 * The engine only contacts api.wordpress.org and downloads.wordpress.org
 * (reference checksums and official packages for the integrity check).
 * TLS verification is WordPress' default and is never turned off here:
 * on a compromised host an "all clean" answer must not be attacker-supplied.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

class Elderward_WP_Http implements Elderward\Engine\Http
{
    private function args($timeout)
    {
        return array(
            'timeout'     => $timeout,
            'redirection' => 3,
            'user-agent'  => 'elderward/' . ELDERWARD_VERSION . '; ' . home_url('/'),
        );
    }

    public function get($url)
    {
        $response = wp_remote_get($url, $this->args(60));
        if (is_wp_error($response)) {
            return array(0, '');
        }
        return array((int) wp_remote_retrieve_response_code($response), (string) wp_remote_retrieve_body($response));
    }

    public function download($url, $dest)
    {
        // Package zips can be tens of MB: stream straight to disk.
        $args = $this->args(300);
        $args['stream'] = true;
        $args['filename'] = $dest;
        $response = wp_remote_get($url, $args);
        if (is_wp_error($response)) {
            return 0;
        }
        return (int) wp_remote_retrieve_response_code($response);
    }
}
