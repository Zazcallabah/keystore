. ".\keystore.ps1"

Describe "Filters" {
	It "string GetBytes" {
		$b = "abcd" | GetBytes
		$b.length | should be 4
		$b[0] | should be 97
		$b[1] | should be 98
		$b[2] | should be 99
		$b[3] | should be 100
	}
	It "bytes GetString" {
		$s = @(97,98,99,100) | GetString
		$s | should be "abcd"
	}
	It "string FromBase64" {
		$b = "YWJjZA==" | FromBase64
		$b.length | should be 4
		$b[0] | should be 97
		$b[1] | should be 98
		$b[2] | should be 99
		$b[3] | should be 100
	}
	It "bytes ToBase64" {
		$s = @(97,98,99,100) | ToBase64
		$s | should be "YWJjZA=="
	}
	It "bytes ToHex" {
		$s = @(97,98,99,100) | ToHex
		$s | should be "61626364"
		$s.GetType().Name | should be "String"
	}
	It "string SHA1" {
		$s = "abcd" | SHA1
		$s | should be "81fe8bfe87576c3ecb22426f8e57847382917acf"
		$s.GetType().Name | should be "String"
	}
}

Describe "MakeCert" {
	It "can make cert" {
		$script:cert = Make-KeystoreCertificate "testcert1234"
		$script:cert.Subject | should be "CN=testcert1234"
	}
}

Describe "Keyfile" {
	It "can get keystore path" {
		$c = Get-LocalKeystore
		$c | should be "$($env:userprofile)\.keystore"
	}
	It "can get key path" {
		$c = Get-KeyFilePath "abcd"
		$c | should be "$($env:userprofile)\.keystore\81fe8bfe87576c3ecb22426f8e57847382917acf"
	}
}

Describe "Encrypt and Decrypt" {
	It "can encrypt" {
		$bytes = @(1,2,3,4)
		$encrypted = Encrypt $bytes $script:cert
		$encrypted.GetType().Name | should be "Object[]"
		$encrypted.length | should not be 4
		$encrypted[0] | should not be 1
		$encrypted[1] | should not be 2
		$encrypted[2] | should not be 3
		$encrypted[3] | should not be 4
	}
	It "can decrypt" {
		$bytes = @(1,2,3,4)
		$encrypted = Encrypt $bytes $script:cert
		$decrypted = Decrypt $encrypted $script:cert
		$decrypted.GetType().Name | should be "Object[]"
		$decrypted.length | should be 4
		$decrypted[0] | should be 1
		$decrypted[1] | should be 2
		$decrypted[2] | should be 3
		$decrypted[3] | should be 4
	}
}

Describe "Get and Set KeystoreData" {
	It "can encrypt" {
		$message = "aoeu"
		$result = Set-KeystoreData -keyname a -data $message -cert "CN=testcert1234"
		$result | should be "aoeu"
		Test-Path (Get-KeyFilePath "a") | should be $true
	}
	It "can decrypt" {
		$message = "aoeu"
		Set-KeystoreData -keyname a -data $message -cert "CN=testcert1234"
		$result = Get-KeystoreData -keyname a
		$result | should be "aoeu"
	}
}

Describe "Get and Set KeystoreCredential" {
	It "can encrypt" {
		$result = Set-KeystoreCredential -keyname "b" -username "aoeu" -password "pass" -cert "CN=testcert1234"
		Test-Path (Get-KeyFilePath "b") | should be $true
	}
	It "can decrypt" {
		Set-KeystoreCredential -keyname ab -username "aoeu" -password "pass" -cert "CN=testcert1234"
		$result = Get-KeystoreCredential -keyname ab
		$result.username | should be "aoeu"
		$result.getnetworkcredential().password | should be "pass"
	}
}
rm $script:cert.pspath
