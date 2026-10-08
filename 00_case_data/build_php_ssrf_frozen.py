"""Build the current frozen PHP SSRF JSONL mini-set."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROWS = [
    {
        "cve_id": "CVE-2026-55599",
        "language": "PHP",
        "repo": "phpseclib/phpseclib",
        "description": "phpseclib SSRF through AIA fetchURL; fetches issuer URLs during certificate validation.",
        "cwe": ["CWE-918"],
        "source": "phpseclib/File/X509.php::fetchURL()",
        "vuln_code": """    /**
     * Fetches a URL
     */
    private static function fetchURL(string $url): ?string
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return null;
        }
        $host = $parts['host'];
        $port = $parts['port'] ?? 80;

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ip = $host;
            if (preg_match('/^::ffff:(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})$/i', $ip, $m)) {
                $ip = $m[1];
            }
        } else {
            $records = dns_get_record($host, DNS_A | DNS_AAAA);
            if (!$records) {
                return null;
            }
            $ip = $records[0]['ip'] ?? $records[0]['ipv6'] ?? null;
            if ($ip === null) {
                return null;
            }
        }

        if (!(static::$urlFetchCallback)($host, $ip, $port, $parts['scheme'])) {
            return null;
        }

        $target = strpos($ip, ':') !== false ? "[$ip]" : $ip;
        switch ($parts['scheme']) {
            case 'http':
                $fsock = @fsockopen($target, $port);
                if (!$fsock) {
                    return null;
                }
                break;
            case 'https':
                $fsock = @stream_socket_client("ssl://{$target}:{$port}");
                if (!$fsock) {
                    return null;
                }
                break;
            default:
                return null;
        }
        return stream_get_contents($fsock);
    }""",
    },
    {
        "cve_id": "CVE-2026-48555",
        "language": "PHP",
        "repo": "spatie/laravel-medialibrary",
        "description": "Spatie Media Library SSRF through addMediaFromUrl on remote URLs.",
        "cwe": ["CWE-918"],
        "source": "src/InteractsWithMedia.php::addMediaFromUrl()",
        "vuln_code": """    /**
     * Add a remote file to the media library.
     *
     * @throws FileCannotBeAdded
     */
    public function addMediaFromUrl(string $url, array|string ...$allowedMimeTypes): FileAdder
    {
        if (! Str::startsWith($url, ['http://', 'https://'])) {
            throw InvalidUrl::doesNotStartWithProtocol($url);
        }

        $downloader = config('media-library.media_downloader', DefaultDownloader::class);
        $temporaryFile = (new $downloader)->getTempFile($url);
        $this->guardAgainstInvalidMimeType($temporaryFile, $allowedMimeTypes);

        $filename = basename(parse_url($url, PHP_URL_PATH));
        $filename = urldecode($filename);

        if ($filename === '') {
            $filename = 'file';
        }

        if (! Str::contains($filename, '.')) {
            $mediaExtension = explode('/', mime_content_type($temporaryFile));
            $filename = "{$filename}.{$mediaExtension[1]}";
        }

        return app(FileAdderFactory::class)
            ->create($this, $temporaryFile)
            ->usingName(pathinfo($filename, PATHINFO_FILENAME))
            ->usingFileName($filename);
    }""",
    },
    {
        "cve_id": "CVE-2025-54370",
        "language": "PHP",
        "repo": "phpoffice/phpspreadsheet",
        "description": "PhpSpreadsheet SSRF through Drawing::setPath on URL-like paths.",
        "cwe": ["CWE-918"],
        "source": "src/PhpSpreadsheet/Worksheet/Drawing.php::setPath()",
        "vuln_code": """    /**
     * Set Path.
     *
     * @return $this
     */
    public function setPath(string $path, bool $verifyFile = true, ?ZipArchive $zip = null): static
    {
        $this->isUrl = false;
        if (preg_match('~^data:image/[a-z]+;base64,~', $path) === 1) {
            $this->path = $path;
            return $this;
        }

        $this->path = '';
        if (filter_var($path, FILTER_VALIDATE_URL)) {
            if (!preg_match('/^(http|https|file|ftp|s3):/', $path)) {
                throw new PhpSpreadsheetException('Invalid protocol for linked drawing');
            }
            $this->isUrl = true;
            $ctx = null;
            if (str_starts_with($path, 'https:') || str_starts_with($path, 'http:')) {
                $ctx = stream_context_create(['http' => ['header' => ['Accept: image/*']]]);
            }
            $imageContents = @file_get_contents($path, false, $ctx);
            if ($imageContents === false) {
                throw new PhpSpreadsheetException('Unable to read image from URL');
            }
            $this->path = $path;
            return $this;
        }

        $this->path = $path;
        return $this;
    }""",
    },
    {
        "cve_id": "CVE-2026-52840",
        "language": "PHP",
        "repo": "alextselegidis/easyappointments",
        "description": "EasyAppointments CalDAV connection test SSRF through connect_to_server().",
        "cwe": ["CWE-918"],
        "source": "application/controllers/Caldav.php::connect_to_server()",
        "vuln_code": """    /**
     * Connect to the target CalDAV server
     */
    public function connect_to_server(): void
    {
        try {
            method('post');

            check('provider_id', 'numeric');
            check('caldav_url', 'string');
            check('caldav_username', 'string');
            check('caldav_password', 'string');

            $provider_id = request('provider_id');
            $user_id = session('user_id');

            if (cannot('edit', PRIV_USERS) && (int) $user_id !== (int) $provider_id) {
                throw new RuntimeException('You do not have the required permissions for this task.');
            }

            $caldav_url = request('caldav_url');
            $caldav_username = request('caldav_username');
            $caldav_password = request('caldav_password');

            $this->caldav_sync->test_connection($caldav_url, $caldav_username, $caldav_password);

            $provider = $this->providers_model->find($provider_id);
            $provider['settings']['caldav_sync'] = true;
            $provider['settings']['caldav_url'] = $caldav_url;
            $provider['settings']['caldav_username'] = $caldav_username;
            $provider['settings']['caldav_password'] = $caldav_password;
            $this->providers_model->save($provider);

            json_response(['success' => true]);
        } catch (GuzzleException | InvalidArgumentException $e) {
            log_message('error', 'CalDAV - Connection test failed: ' . $e->getMessage());
            json_response(['success' => false, 'message' => lang('calendar_sync_failed')]);
        } catch (Throwable $e) {
            json_exception($e);
        }
    }""",
    },
]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="data/interim/php_ssrf_frozen_v01.jsonl")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for row in ROWS:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(ROWS)} rows -> {out}")


if __name__ == "__main__":
    main()
