<?php

namespace AdityaDarma\LaravelJwtSso\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static static setSecretKey($secretKey)
 * @method static static encryptPayload()
 * @method static static setPayload(array $payload)
 * @method static array getPayload()
 * @method static object getObjectPayload()
 * @method static string generate()
 * @method static static validate(string $token)
 *
 * @see \AdityaDarma\LaravelJwtSso\Jwt
 */
class JwtSso extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'jwt-sso';
    }
}