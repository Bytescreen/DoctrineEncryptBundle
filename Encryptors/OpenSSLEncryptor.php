<?php

namespace Bytescreen\DoctrineEncryptBundle\Encryptors;

/**
 * Base class for openssl encryption
 * 
 * @author Bytescreen
 */
abstract class OpenSSLEncryptor implements EncryptorInterface {

    protected $method = "";
    
    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var string
     */
    private $initializationVector;

    /**
     * {@inheritdoc}
     */
    public function __construct($key) {
        $this->secretKey = md5($key);
        $this->initializationVector = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->method));
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data) {

        if(is_string($data)) {
            return trim(base64_encode(openssl_encrypt(
                $data,
                $this->method,
                $this->secretKey,
                OPENSSL_RAW_DATA,
                $this->initializationVector
            ))). "<ENC>";
        }

        return $data;

    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($data) {

        if(is_string($data)) {

            $data = str_replace("<ENC>", "", $data);

            return trim(openssl_decrypt(
                base64_decode($data),
                $this->method,
                $this->secretKey,
                OPENSSL_RAW_DATA,
                $this->initializationVector
            ));
        }

        return $data;
    }
}
