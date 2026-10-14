# Passphrase-based String Crypto

Encrypt and decrypt short strings using a passphrase. 

This is a .NET 10 (LTS) console app, i.e., a command line app with the name `scrypto` (`scrypto.exe` on Windows).

## Secure streaming interface

Use the streaming commands for secret material. They read the value through standard input, prompt for the
passphrase without echo on the controlling terminal, and write exactly one result to standard output. Both standard
input and standard output must be redirected; this prevents accidental terminal display and keeps the plaintext and
passphrase out of process arguments and ordinary shell history.

Encryption usage:

    producer-command | scrypto encrypt-stdin > ciphertext.txt

Decryption usage:

    scrypto decrypt-stdin < ciphertext.txt | consumer-command

`encrypt-stdin` accepts exactly one plaintext line and asks for the passphrase twice. `decrypt-stdin` accepts wrapped
or unwrapped ciphertext and asks once. Prompts and errors use standard error so standard output can remain a clean
pipe. A pipe cannot protect secrets from a compromised host, privileged process, terminal recorder, crash dump, or
the producer/consumer programs.

The hidden prompt is supported on Windows and Linux. Use a native Linux build inside WSL; a Windows build invoked
through WSL interop does not have a reliable Windows console input channel.

The original argument-based interface remains available for compatibility, but it is unsafe for secret material:
both the value and passphrase can appear in process listings and shell history.

## Legacy encryption interface

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


## Legacy decryption interface

Decryption usage:

    scrypto decrypt "<ciphertext>" "<passphrase>"
    
Examples:

    scrypto decrypt "VUuW8IKdZkIf4dXHKQ^EadXjuZ4AEkqeg2CYRac#h5TKDZDxcSWE6Mjek2swf6Ra8^DxhgY~qck=" "password 123"
    scrypto decrypt "VUuW8IKd ZkIf4dXH KQ^EadXj uZ4AEkqe g2CYRac# h5TKDZDx cSWE6Mje k2swf6Ra 8^DxhgY~ qck=" "password 123"
    
Example decryption output:

    message to encrypt
    
## Base64 Alternative Alphabet

Wrap the command arguments in double quotes of they contain spaces or other special characters that may affect how
the shell or command window you are using interprets the arguments. For the decryption command it is recommended to
always wrap the ciphertext argument in double quotes, as some of the base64 characters are special characters in most
command shells.

The base64 alternative alphabet is the same as the standard base64 alphabet, with the following substitutions:

    0 (digit zero)    ->  $
    1 (digit 1)       ->  #
    O (upper case O)  ->  ;
    l (lower case L)  ->  ~
    o (lower case O)  ->  ^

## Cryptographic Algorithm

The passphrase is transformed into a 256-bit encryption key using PBKDF2-HMAC-SHA1 with 2,000,000 iterations and a
random 8 byte (64 bit) salt.

Encryption is performed using the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM); this 
uses a further 12 random nonce bytes. The PBKDF2 salt and AES-GCM nonce bytes are encoded in the output,
and therefore repeated calls to encrypt the same string with the same passphrase will produce completely
different output.

The ciphertext also contains a 16-byte GCM authentication tag and an authenticated two-byte plaintext length. The
format has no embedded version or KDF parameters. Preserve the software/source version and recovery instructions
with long-lived records. The secure streaming commands deliberately retain the original 2021 ciphertext format;
the published fixed ciphertext test vector checks backward-compatible decryption.
