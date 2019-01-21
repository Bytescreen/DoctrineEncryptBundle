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
     * {@inheritdoc}
     */
    public function __construct($key) {
        $this->secretKey = md5($key);
    }

    
    /**
     * {@inheritdoc}
     */
    public function encrypt($data) {

        if(is_string($data)) {
            
            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->method));
            
            return trim(base64_encode(openssl_encrypt(
                $data,
                $this->method,
                $this->secretKey,
                OPENSSL_RAW_DATA,
                $iv
            ))). ">>". bin2hex($iv). "<ENC>";
        }

        return $data;

    }

    
    /**
     * {@inheritdoc}
     */
    public function decrypt($data) {

        if(is_string($data)) {

            $data = str_replace("<ENC>", "", $data);
            $data = explode(">>", $data);
            $iv   = hex2bin($data[1]);
            $data = $data[0];

            return trim(openssl_decrypt(
                base64_decode($data),
                $this->method,
                $this->secretKey,
                OPENSSL_RAW_DATA,
                $iv
            ));
        }

        return $data;
    }
    
}
