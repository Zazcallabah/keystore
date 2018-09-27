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
		$c = Make-KeystoreCertificate "testcert1234"
		$c.Subject | should be "CN=testcert1234"
		rm $c.pspath
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