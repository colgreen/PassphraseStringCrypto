# Passphrase-based String Crypto

Encrypt and decrypt short strings using a passphrase. 

This is a dotnet core console app, i.e., a command line app with the name 'scrypto.exe'

## Encryption

Encryption usage:

    scrypto encrypt "<plaintext>" "<passphrase>"
    
Examples:

    scrypto encrypt message-to-encrypt password123
    scrypto encrypt "message to encrypt" "password 123"
    
Example encryption output:

    VUuW8IKd ZkIf4dXH KQ^EadXj uZ4AEkqe g2CYRac# h5TKDZDx cSWE6Mje k2swf6Ra 8^DxhgY~ qck=
    
    VUuW8IKdZkIf4dXHKQ^EadXjuZ4AEkqeg2CYRac#h5TKDZDxcSWE6Mjek2swf6Ra8^DxhgY~qck=
    
The output is base64 with an alternative alphabet to avoid characters that are easily misread.
The string is output twice, once with output broken into 8 character blocks for easy reading, and again as a single run/block with no spaces.


## Decryption

Decryption usage:

    scrypto decrypt "<ciphertext>" "<passphrase>"
    
Examples:

    scrypto decrypt "VUuW8IKdZkIf4dXHKQ^EadXjuZ4AEkqeg2CYRac#h5TKDZDxcSWE6Mjek2swf6Ra8^DxhgY~qck=" password123
    scrypto encrypt "VUuW8IKd ZkIf4dXH KQ^EadXj uZ4AEkqe g2CYRac# h5TKDZDx cSWE6Mje k2swf6Ra 8^DxhgY~ qck=" "password 123"
    
Example decryption output:

    message to encrypt
    
## Base64 Alternative Alphabet

Wrap the command arguments in double quotes of they contain spaces or other special characters that may affect how
the shell or command window you are using interprets the arguments. For the decryption command it is recommended to
always wrap the ciphertext argument in double quotes, as some of the base64 characters are special characters in most
command shells.

The base64 alternative alphabet is the same as the standard base64 alphabet, with the following substitions:

    0 (digit zero)    ->  $
    1 (digit 1)       ->  #
    O (upper case O)  ->  ;
    l (lower case L)  ->  ~
    o (lower case O)  ->  ^

## Cryptographic Algorithm

The passphrase is transformed into an encryption key using PBKDF2 using a random 8 byte (64 bit) salt.

Encryption is peformed using the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM); this 
uses a further 12 random nonce bytes. The PBKDF2 salt and AEC-GCM nonce bytes are encoded in the output,
and therefore repeated calls to encrypt the same string with the same passphrase will produce completely
different output.



    
    
