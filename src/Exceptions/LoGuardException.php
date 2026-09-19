<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Exceptions;

use RuntimeException;

/**
 * Base exception for all LoGuard SDK errors.
 *
 * Mirrors the exception hierarchy of the other LoGuard SDKs
 * (Python LoGuardError, Node LoGuardError, Go/loguard errors, C# LoGuardException)
 * so callers can catch \LoGuard\Sdk\Exceptions\LoGuardException for "anything
 * went wrong talking to LoGuard" regardless of language.
 */
class LoGuardException extends RuntimeException
{
}
