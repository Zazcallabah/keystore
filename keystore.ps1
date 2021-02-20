filter GetBytes {
	[System.Text.Encoding]::UTF8.GetBytes( $_ )
}

filter GetString {
	param([Parameter(ValueFromPipeline)][byte]$b)
	begin {
		$array = @()
	}
	process {
		$array += $b
	}
	end {
		return [System.Text.Encoding]::UTF8.GetString( $array )
	}
}

filter ToBase64 {
	param([Parameter(ValueFromPipeline)][byte]$b)
	begin {
		$array = @()
	}
	process {
		$array += $b
	}
	end {
		return [System.Convert]::ToBase64String( $array )
	}
}

filter FromBase64 {
	[System.Convert]::FromBase64String( $_ )
}

filter ToHex {
	param([Parameter(ValueFromPipeline)][byte]$b)
	begin {
		$str = new-object System.Text.StringBuilder
	}
	process {
		$r = $str.Append($b.ToString( "X2" ))
	}
	end {
		$str.ToString()
	}
}

filter SHA1 {
	$sha1 = (new-object System.Security.Cryptography.SHA1Managed).ComputeHash( ($_ | GetBytes) )
	return $sha1 | ToHex
}

function Get-LocalKeyStore {
	$localStore = Join-Path $env:userprofile ".keystore"
	if( !(test-path $localStore ) ) {
		mkdir $localStore | out-null
	}
	$localStore
}

function Get-KeyFilePath {
	param($keyName)
	Join-Path (Get-LocalKeyStore) ($keyName | SHA1)
}


function Get-AvailableCertificates {
	ls -Recurse "Cert:\CurrentUser\My"
}

function Get-Cert {
	param(
		[Parameter(mandatory=$true,parametersetname="Subject")]
		$subject,
		[Parameter(mandatory=$true,parametersetname="Thumbprint")]
		$thumbprint
	)
	Get-AvailableCertificates | ?{ $_.Subject -eq $subject -or $_.Thumbprint -eq $thumbprint } | select -First 1
}

function Get-MakeCertPath {
#	if( Get-Command makecert -ErrorAction SilentlyContinue ) {
#		return "makecert"
#	}
	if(Test-Path "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\") {
		$makeCertPath = ls "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\*\bin\makecert.exe" | select -ExpandProperty Fullname -last 1
	}
	if( $makeCertPath ) {
		return $makeCertPath
	}
	return "$PSScriptRoot\makecert.exe"
}

function Get-DefaultCertificate {
	return Get-Cert -Subject "CN=keystore@$($env:username)"
}

function Make-KeystoreCertificate {
	param($commonName="keystore@$($env:UserName)")
	[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | out-null
	$subject = "CN=$commonName"
	$cert = Get-Cert -subject $subject
	if( $cert -eq $null ) {
		$makecert = Get-MakeCertPath
		$certresult = & "$makecert" -r -sk keystore -sky Exchange -n $subject -ss My
		Write-Host "Created certificate with subject $subject."
		$cert = Get-Cert -subject $subject
	}
	Write-Host "Using certificate with subject $($cert.Subject) thumbprint $($cert.Thumbprint)"
	$cert
}

function Delete-KeystoreData {
	param( $keyName )
	$keyFile = Get-KeyFilePath $keyName
	if( Test-Path -PathType Leaf $keyFile ) {
		rm $keyFile
	}
}

function Delete-KeystoreCredential {
	param( $keyName )
	Delete-KeystoreData $keyname
}

function Decrypt {
	param( [byte[]] $encryptedBytes, [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert )
	$cms = New-Object Security.Cryptography.Pkcs.EnvelopedCms
	$cms.Decode($encryptedBytes)
	$cms.Decrypt($cert)
	return $cms.ContentInfo.Content
}

function Encrypt {
	param( [byte[]] $bytes, [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert )
	$contentInfo = New-Object Security.Cryptography.Pkcs.ContentInfo -argumentList (,$bytes)
	$cms = New-Object Security.Cryptography.Pkcs.EnvelopedCms $contentInfo
	$recipient = New-Object System.Security.Cryptography.Pkcs.CmsRecipient($cert)
	$cms.Encrypt($recipient)
	return $cms.Encode()
}

function Get-KeystoreData {
	param(
		[parameter(mandatory=$true)]
		[string] $keyName
	)
	[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | out-null

	$keyFile = Get-KeyFilePath $keyName
	if( Test-Path -PathType Leaf $keyFile ) {
		$keyData = gc -Encoding Utf8 -Path $keyFile
		$cert = Get-Cert -thumbprint $keyData[0]
		if(!$cert) {
			throw ("Cannot find the requested certificate: {0}" -f $keyData[0])
		}
		$keyDataBytes = $keyData[2] | FromBase64
		$data = Decrypt $keyDataBytes $cert | GetString
		if( $keyData[1] -eq "json" )
		{
			return $data | ConvertFrom-Json
		}
		return $data
	}
}

function Set-KeystoreData {
	param(
		[parameter(mandatory=$true)]
		[string] $keyName,
		[parameter(mandatory=$true)]
		$data,
		$cert
	)
	[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | out-null

	if( $cert -eq $null ) {
		$cert = Get-DefaultCertificate
	}
	if( $cert -eq $null ){
		$cert = Make-KeystoreCertificate
	}
	if( $cert -eq $null ) {
		throw "Couldn't find proper certificate"
		return
	}

	if( $data -eq $null -or $data -eq "" ) {
		throw "Must specify data to encrypt"
		return
	}
	if( $cert.GetType().Name -eq "String" ) {
		$subject = $cert
		$cert = Get-Cert -subject $subject
		if( $cert -eq $null ) {
			throw "no cert found with subject $subject"
		}
	}

	if( $data.GetType().Name -eq "String" ) {
		$stringdata = $data
		$type = "string"
	}
	else
	{
		$stringdata = $data | ConvertTo-Json -Depth 99
		$type = "json"
	}
	$keyfile = Get-KeyFilePath $keyName
	$byteData = $stringData | GetBytes
	$encrypted = Encrypt $byteData $cert | ToBase64
	$keydata = @( $cert.Thumbprint, $type, $encrypted )
	set-content -Encoding Utf8 -Path $keyfile -Value $keydata
	$retrievedData = Get-KeystoreData -keyName $keyName
	if( $retrievedData -eq $null ) {
		throw "Failed to encrypt data with keyname $keyname"
	}

	if( ($retrievedData|ConvertTo-Json -Depth 99) -ne ($data|ConvertTo-Json -Depth 99) ) {
		throw "Failed to encrypt data with keyname $keyname"
	}
	return $retrievedData
}

function Get-KeystoreCredential {
	param( $keyName )
	$data = Get-KeystoreData -keyName $keyName
	if($data -and $data.u -and $data.p) {
		return new-object System.Management.Automation.PSCredential( $data.u, (ConvertTo-SecureString -AsPlainText -Force -String $data.p) )
	}
}

function Set-KeystoreCredential {
	param(
		[parameter(mandatory=$true,position=0)]
		[string] $keyName,
		[parameter(mandatory=$true,position=1,parametersetname="UsernamePassword")]
		[string] $username,
		[parameter(mandatory=$true,position=2,parametersetname="UsernamePassword")]
		[string] $password,
		[parameter(mandatory=$true,position=1,parametersetname="PSCredential")]
		[System.Management.Automation.PSCredential] $credential,
		$cert
	)

	if( $credential -ne $null ) {
		$networkcredential = $credential.getNetworkCredential()
		$username = $networkcredential.Username
		$password = $networkcredential.Password
	}

	if( !($username -and $password) ) {
		throw "Must specify credential or non-empty username+password"
		return
	}

	$data = Set-KeystoreData -keyName $keyName -data @{"u"=$username;"p"=$password} -cert $cert

	if( $data -eq $null ) {
		throw "Failed to encrypt credential with keyname $keyname"
	}

	if($data.u -and $data.p) {
		return new-object System.Management.Automation.PSCredential( $data.u, (ConvertTo-SecureString -AsPlainText -Force -String $data.p) )
	}
	else
	{
		throw "Failed to encrypt credential with keyname $keyname"
	}
}


