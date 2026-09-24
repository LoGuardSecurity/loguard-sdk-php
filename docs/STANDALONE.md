# LoGuard PHP SDK — standalone installation

Composer is the preferred installation method. Use this standalone package
when the deployment environment cannot install Composer packages.

## Requirements

- PHP 8.1 or newer
- cURL, JSON and mbstring extensions
- HTTPS access to the LoGuard API

The standalone package contains no third-party runtime dependencies.

## Installation

Extract the archive into an application-owned directory outside the public web
root. For CodeIgniter 3, a suitable location is:

    application/third_party/loguard/

Load the SDK once during application bootstrap:

    require_once APPPATH . 'third_party/loguard/autoload.php';

Do not load PHP code directly from a remote URL or CDN at runtime.

## CodeIgniter 3

After loading `autoload.php`, configure the SDK in the same way as the Composer
package. Keep the API key in an environment variable or secret manager. Never
place it in source control or directly in `hooks.php`.

The CodeIgniter 3 adapter is included. Laravel and PSR-15 adapters require
their respective framework interfaces and should normally use Composer.

## Durable spool worker

The standalone worker is available at:

    php application/third_party/loguard/bin/loguard-spool-worker

Run it under a process manager or scheduled worker. The application request
remains fail-open while queued events stay in the local spool for delivery.

## Integrity verification

Verify the archive before extraction.

macOS:

    shasum -a 256 -c loguard-php-sdk-VERSION.zip.sha256

Linux:

    sha256sum -c loguard-php-sdk-VERSION.zip.sha256

Download the archive and checksum from the same official LoGuard release.
Do not install standalone archives received through chat, email attachments
or untrusted mirrors.
