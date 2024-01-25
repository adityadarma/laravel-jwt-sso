<?php

namespace AdityaDarma\LaravelJwtSso;

use AdityaDarma\LaravelJwtSso\Exception\DecryptException;
use JsonException;
use function PHPUnit\Framework\isJson;

class Crypt
{
    private string $secretKey;
    private string $dataKey = 'xZStOtGzCAN0yo6Y2srNuc0OOAGbg2Md';

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
     * @param mixed $value
     * @return string
     * @throws JsonException
     */
    public function encrypt(mixed $value): string
    {
        $iv = substr(hash('sha256', $this->dataKey), 0, 16);
        $options = 0;

        $value = is_array($value) ? json_encode($value, JSON_THROW_ON_ERROR) : $value;

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
     * @param mixed $value
     * @return mixed
     * @throws DecryptException
     * @throws JsonException
     */
    public function decrypt(mixed $value): mixed
    {
        $iv = substr(hash('sha256', $this->dataKey), 0, 16);
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
            throw new DecryptException('Cant decrypt this value:'. $value);
        }

        return $this->isJsonString($decode)
            ? json_decode($decode, false, 512, JSON_THROW_ON_ERROR)
            : $decode;
    }

    public function isJsonString($string): bool
    {
        return is_string($string) && is_array(json_decode($string, true)) && (json_last_error() === JSON_ERROR_NONE);
    }
}
