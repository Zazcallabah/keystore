filter GetBytes {
	[System.Text.Encoding]::UTF8.GetBytes( $_ )
}

filter GetString {
	[System.Text.Encoding]::UTF8.GetString( $_ )
}

filter ToBase64 {
	[System.Convert]::ToBase64String( $_ )
}

filter FromBase64 {
	[System.Convert]::FromBase64String( $_ )
}

filter ToHex {
	$_.ToString( "X2" )
}

filter SHA1 {
	$sha1 = (new-object System.Security.Cryptography.SHA1Managed).ComputeHash( ($_ | GetBytes) )
	($sha1 | ToHex) -join ""
}

function getLocalKeyStore {
	$localStore = Join-Path $env:userprofile ".keystore"
	if( !(test-path $localStore ) ) {
		mkdir $localStore | out-null
	}
	$localStore
}

function getAvailableCerts {
	ls -Recurse cert:
}

function getCert {
	param($subject)
	getAvailableCerts | ?{ $_.Subject -eq $subject } | select -First 1
}

function getMakeCertPath {
	if( Get-Command makecert -ErrorAction SilentlyContinue ) {
		return "makecert"
	}
	$makeCertPath = ls "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\*\bin\makecert.exe" | select -ExpandProperty Fullname -last 1
	if( $makeCertPath )
	{
		return $makeCertPath
	}
	return "$PSScriptRoot\makecert.exe"
}

function makeKeystoreCertificate {
	param($commonName="keystore@$($env:UserName)")
	[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | out-null
	$subject = "CN=$commonName"
	$cert = getCert $subject
	if( $cert -eq $null ) {
		$makecert = getMakeCertPath
		& "$makecert" -r -sk keystore -sky Exchange -n $subject -ss My | Out-Host
		Write-Host "Created certificate with subject $subject."
		$cert = getCert $subject
	}
	Write-Host "Using certificate with subject $($cert.Subject) thumbprint $($cert.Thumbprint)"
	$cert
}
