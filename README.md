# Keystore
Powershell scripts for encrypting and decrypting data using an X.509 certificate.

## background

I finally got tired of rewriting the same powershell encryption functions over and over again, so from now on I'll just save these here so I can easily find them the next time I need them. The name 'keystore' is a reference to the encryption script module we wrote at my first workplace, which inspired me to write these scripts in the first place.

## todo
everything.

The idea is to have a designated "keystore", a folder probably in %appdata% or possibly in the user folder. In that folder encrypted data is stored. Each piece of encrypted data is called a "key". Each key has a label that can be used to get and set its value.

So you do 

    ./Set-KeystoreData.ps1 -keyname "mykey" -data "secret data"

to save encrypted data and you do 

    ./Get-KeystoreData.ps1 -keyname "mykey"

to later retrieve it.

The data is called key primarily because of nostalgia reasons, and it is also because of nostalgia that the encrypted files' names are the SHA1 hash of the key label.

### code snippets

To get an UTF8 string from a byte array and vice verse:

    $str = [System.Text.Encoding]::UTF8.GetString($bytes)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)

To convert to and from base-64 encoding:

    $base64 = [System.Convert]::ToBase64String($bytes)
    $bytes = [System.Convert]::FromBase64String($base64)

To get a sha1 hash of a byte array:

    (new-object System.Security.Cryptography.SHA1Managed).ComputeHash($bytes)

Byte array as hexadecimal string:

    $s = new-object System.Text.StringBuilder
    foreach($b in $bytes){ $s.Append($b.ToString("X2")) }

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
The first line is the thumbprint of the cert used to encrypt the data.
The second line is a type specifier, usually one of string, bin, or json.
The third line is the encrypted data, in base64 encoded form.


## further reading

* https://stackoverflow.com/questions/31002186/encrypt-de-crypt-using-envelopedcms-throws-baddata-exception
