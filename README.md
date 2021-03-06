# Keystore
Powershell scripts for encrypting and decrypting data using an X.509 certificate.

## background

I finally got tired of rewriting the same powershell encryption functions over and over again, so from now on I'll just save these here so I can easily find them the next time I need them. The name 'keystore' is a reference to the encryption script module we wrote at my first workplace, which inspired me to write these scripts in the first place.

## details

The idea is to have a designated "keystore", a folder probably in %appdata% or possibly in the user folder. In that folder encrypted data is stored. Each piece of encrypted data is called a "key". Each key has a label that can be used to get and set its value.

So you do 

    ./Set-KeystoreData.ps1 -keyname "mykey" -data "secret data"

to save encrypted data and you do 

    ./Get-KeystoreData.ps1 -keyname "mykey"

to later retrieve it.

The data is called key primarily because of nostalgia reasons, and it is also because of nostalgia that the encrypted files' names are the SHA1 hash of the key label.

### code snippets

Get a x509 cert from the user cert store:

    $name = "uniquename"
    $cert = ls -Recurse Cert:\CurrentUser\My | ?{ $_.Subject -match "CN=$name" } | select -first 1

Encrypt a byte array using a x509 cert:

    $contentInfo = New-Object Security.Cryptography.Pkcs.ContentInfo -argumentList (,$bytes)
    $cms = New-Object Security.Cryptography.Pkcs.EnvelopedCms $contentInfo
    $recipient = New-Object System.Security.Cryptography.Pkcs.CmsRecipient($cert)
    $cms.Encrypt($recipient)
    $encrypted = $cms.Encode()

Decrypt a byte array using a x509 cert:

    $cms = New-Object Security.Cryptography.Pkcs.EnvelopedCms
    $cms.Decode($encrypted)
    $cms.Decrypt($cert)
    $bytes = $cms.ContentInfo.Content

Use makecert.exe to create a new x509 cert in the current user cert store:

    .\makecert.exe -r -sk keystore -sky Exchange -n "CN=$name" -ss My

### file format

The keystore files consist of three lines of data.

* The first line is the thumbprint of the cert used to encrypt the data.
* The second line is a type specifier, usually one of string, bin, or json.
* The third line is the encrypted data, in base64 encoded form.

### file names and locations

Keystore location should default to a folder named `.keystore` in the user folder.

    $location = Join-Path $env:USERPROFILE ".keystore"

A keystore file name is the SHA1 hash of the key name as a hexadecimal string without a "0x" prefix.

A keystore certificate can be any X.509 certificate that can encrypt and decrypt data, but defaults to a certificate with a common name `keystore@user`.

    $commonName = "keystore@$($env:USERNAME)"

If no certificate is given when setting keystore data, a certificate with this name will be created and placed in the current user cert store.

Since the keystore file contains the thumbprint of the cert that encrypted it, the entire cert store will be searched for a cert with that thumbprint to use for decryption.

## further reading

* https://stackoverflow.com/questions/31002186/encrypt-de-crypt-using-envelopedcms-throws-baddata-exception

## License

* https://opensource.org/licenses/MIT