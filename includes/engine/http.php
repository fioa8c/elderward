<?php
namespace Elderward\Engine;

////////////////
// Outbound HTTP. The engine only ever talks to api.wordpress.org and
// downloads.wordpress.org (reference checksums and official packages).
// This tool runs on already-compromised hosts: never disable TLS
// verification, or the "all clean" answer can be attacker-supplied.
//
// Inside WordPress the plugin injects an implementation built on the
// WordPress HTTP API; the standalone CLI uses CurlHttp below.
//////////////

interface Http
{
    // Returns array($status, $body); status 0 on transport failure.
    public function get($url);
    // Streams the response body into $dest. Returns the HTTP status code
    // (0 on transport failure).
    public function download($url, $dest);
}

class CurlHttp implements Http
{
    public function get($url)
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, array(
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT        => 60,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT      => 'elderward',
            ));
            $body = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            return array((false === $body) ? 0 : $status, (string) $body);
        }

        $context = stream_context_create(array('http' => array(
            'timeout'       => 60,
            'user_agent'    => 'elderward',
            'ignore_errors' => true,
        )));
        $body = @file_get_contents($url, false, $context);
        $status = isset($http_response_header) ? self::status_from_response_headers($http_response_header) : 0;
        return array($status, (false === $body) ? '' : $body);
    }

    public function download($url, $dest)
    {
        // Package zips can be tens of MB: stream to disk instead of buffering.
        if (function_exists('curl_init')) {
            $fh = @fopen($dest, 'w');
            if (false === $fh) {
                return (0);
            }
            $ch = curl_init($url);
            curl_setopt_array($ch, array(
                CURLOPT_FILE           => $fh,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT        => 300,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT      => 'elderward',
            ));
            $ok = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            fclose($fh);
            return ((false !== $ok) ? $status : 0);
        }

        // No curl: stream through fopen so the zip never sits in memory.
        $context = stream_context_create(array('http' => array(
            'timeout'       => 300,
            'user_agent'    => 'elderward',
            'ignore_errors' => true,
        )));
        $src = @fopen($url, 'r', false, $context);
        if (false === $src) {
            return (0);
        }
        $status = isset($http_response_header) ? self::status_from_response_headers($http_response_header) : 0;
        $dst = @fopen($dest, 'w');
        if (false === $dst) {
            fclose($src);
            return (0);
        }
        $copied = @stream_copy_to_stream($src, $dst);
        fclose($src);
        fclose($dst);
        return ((false === $copied) ? 0 : $status);
    }

    public static function status_from_response_headers($headers)
    {
        // With redirects the array holds several header blocks; the last
        // status line is the one for the final response.
        $status = 0;
        if (is_array($headers)) {
            foreach ($headers as $header_line) {
                if (preg_match('@^HTTP/\S+\s(\d{3})@', $header_line, $matches)) {
                    $status = (int) $matches[1];
                }
            }
        }
        return ($status);
    }
}
