<?php

namespace AdityaDarma\LaravelJwtSso;

use AdityaDarma\LaravelJwtSso\Exception\DecryptException;
use AdityaDarma\LaravelJwtSso\Facades\JwtSso;

class Crypt
{
    protected string $secretKey;

    /**
     * Set secret key
     *
     * @param string $secretKey
     * @return $this
     */
    public function setSecretKey(string $secretKey): static
    {
        $this->secretKey = $secretKey;

        return $this;
    }

    /**
     * Encrypt value
     *
     * @param string $value
     * @return string
     */
    public function encrypt(mixed $value): string
    {
        $secret = 'xZStOtGzCAN0yo6Y2srNuc0OOAGbg2Md';
        $iv = substr(hash('sha256', $secret), 0, 16);
        $options = 0;

        $ciphertext = openssl_encrypt(
            $value,
            "AES-256-CBC",
            $this->secretKey,
            $options,
            $iv
        );

        return rtrim(strtr(base64_encode($ciphertext), '+/', '-_'), '=');
    }

    /**
     * Decrypt value
     *
     * @param string $value
     * @return string
     * @throws DecryptException
     */
    public function decrypt(string $value): string
    {
        $secret = 'xZStOtGzCAN0yo6Y2srNuc0OOAGbg2Md';
        $iv = substr(hash('sha256', $secret), 0, 16);
        $options = 0;

        $ciphertext = base64_decode(str_pad(strtr($value, '-_', '+/'), strlen($value) % 4, '=', STR_PAD_RIGHT));
        $decode = openssl_decrypt(
            $ciphertext,
            "AES-256-CBC",
            $this->secretKey,
            $options,
            $iv
        );
        if (!$decode) {
            throw new DecryptException('Cant decrypt this value');
        }

        return $decode;
    }
}