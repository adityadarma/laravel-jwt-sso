<?php

namespace AdityaDarma\LaravelJwtSso\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static string setSecretKey(string $secretKey)
 * @method static string decrypt(string $value)
 * @method static string encrypt(string $value)
 *
 * @see \AdityaDarma\LaravelJwtSso\Crypt
 */
class CryptSso extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'CryptSso';
    }
}