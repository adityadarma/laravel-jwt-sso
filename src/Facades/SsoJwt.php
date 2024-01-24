<?php

namespace AdityaDarma\LaravelJwtSso\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static static setSecretKey($secretKey)
 * @method static static encryptPayload(bool $encrypt)
 * @method static static setPayload(array $payload)
 * @method static array getPayload()
 * @method static object getObjectPayload()
 * @method static string generate()
 * @method static bool validate(string $token)
 *
 * @see \AdityaDarma\LaravelJwtSso\Jwt
 */
class SsoJwt extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'sso-jwt';
    }
}
