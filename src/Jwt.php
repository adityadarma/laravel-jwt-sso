<?php

namespace AdityaDarma\LaravelJwtSso;

use AdityaDarma\LaravelJwtSso\Facades\SsoCrypt;
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
     * @param bool $encrypt
     * @return $this
     */
    public function encryptPayload(bool $encrypt = true): static
    {
        $this->header = array_merge($this->header, [
            'encrypt' => $encrypt
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
            SsoCrypt::setSecretKey($this->secretKey);
            foreach ($this->payload as $key => $value){
                $this->payload[$key] = $value !== null ? SsoCrypt::encrypt($value) : null;
            }
        }
        $payload = json_encode($this->payload, JSON_THROW_ON_ERROR);

        // Encode Payload to Base64Url String
        $base64UrlPayload = $this->encode($payload);

        // Create Signature Hash
        $signature = hash_hmac($this->alg, $base64UrlHeader . "." . $base64UrlPayload, $this->secretKey, true);

        // Encode Signature to Base64Url String
        $base64UrlSignature = $this->encode($signature);

        // Set JWT token
        $this->token = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

        return $this->token;
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
     * @param string $token
     * @return bool
     * @throws JsonException
     */
    public function validate(string $token): bool
    {
        [$headerEncoded, $payloadEncoded, $signatureEncoded] = explode('.', $token);

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
                SsoCrypt::setSecretKey($this->secretKey);
                foreach ($this->payload as $key => $value){
                    $this->payload[$key] = $value !== null ? SsoCrypt::decrypt($value) : null;
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
