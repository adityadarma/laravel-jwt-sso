<?php

namespace AdityaDarma\LaravelJwtSso;

use AdityaDarma\LaravelJwtSso\Facades\CryptSso;
use JsonException;

class Jwt
{
    private string $alg = 'sha256';
    private string $secretKey;
    private array $header = ['typ' => 'JWT', 'alg' => 'HS256'];
    private array $payload = [];
    protected string $token;

    /**
     * Set secret key
     *
     * @param $secretKey
     * @return $this
     */
    public function setSecretKey($secretKey): static
    {
        $this->secretKey = $secretKey;

        return $this;
    }

    /**
     * Set data payload
     *
     * @param array $payload
     * @return $this
     */
    public function setPayload(array $payload): static
    {
        $this->payload = $payload;

        return $this;
    }

    /**
     * Encrypt payload before generate token
     *
     * @return $this
     */
    public function encryptPayload(): static
    {
        $this->header = array_merge($this->header, [
            'encrypt' => true
        ]);

        return $this;
    }

    /**
     * Get data payload
     *
     * @return array
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * Get data payload
     *
     * @return object
     */
    public function getObjectPayload(): object
    {
        return (object) $this->payload;
    }

    /**
     * Generate token
     *
     * @return string
     * @throws JsonException
     */
    public function generate(): string
    {
        // Create token header as a JSON string
        $header = json_encode($this->header, JSON_THROW_ON_ERROR);

        // Encode Header to Base64Url String
        $base64UrlHeader = $this->encode($header);

        // Create token payload as a JSON string
        if(isset($this->header['encrypt']) && $this->header['encrypt']){
            CryptSso::setSecretKey($this->secretKey);
            foreach ($this->payload as $key => $value){
                $this->payload[$key] = CryptSso::encrypt($value);
            }
        }
        $payload = json_encode($this->payload, JSON_THROW_ON_ERROR);

        // Encode Payload to Base64Url String
        $base64UrlPayload = $this->encode($payload);

        // Create Signature Hash
        $signature = hash_hmac($this->alg, $base64UrlHeader . "." . $base64UrlPayload, $this->secretKey, true);

        // Encode Signature to Base64Url String
        $base64UrlSignature = $this->encode($signature);

        // Create JWT
        return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
    }

    /**
     * Set token
     *
     * @param string $token
     * @return static
     */
    public function setToken(string $token): static
    {
        $this->token = $token;

        return $this;
    }

    /**
     * Get token
     *
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Validate token
     *
     * @return bool
     * @throws JsonException
     */
    public function validate(): bool
    {
        [$headerEncoded, $payloadEncoded, $signatureEncoded] = explode('.', $this->token);

        $dataEncoded = "$headerEncoded.$payloadEncoded";
        $signature = $this->decode($signatureEncoded);
        $rawSignature = hash_hmac(
            $this->alg,
            $dataEncoded,
            $this->secretKey,
            true
        );

        if(hash_equals($rawSignature, $signature)){
            $header = json_decode($this->decode($headerEncoded), true, 512, JSON_THROW_ON_ERROR);
            $this->payload = json_decode($this->decode($payloadEncoded), true, 512, JSON_THROW_ON_ERROR);
            if(isset($header['encrypt']) && $header['encrypt']){
                CryptSso::setSecretKey($this->secretKey);
                foreach ($this->payload as $key => $value){
                    $this->payload[$key] = CryptSso::decrypt($value);
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Encode string
     *
     * @param string $string
     * @return array|string
     */
    private function encode(string $string): array|string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($string));
    }

    /**
     * Decode string
     *
     * @param string $string
     * @return bool|string
     */
    private function decode(string $string): bool|string
    {
        $stringData = str_replace(['-', '_'], ['+', '/'], $string);
        $data = str_pad($stringData, strlen($string) % 4, '=', STR_PAD_RIGHT);
        return base64_decode($data);
    }
}
