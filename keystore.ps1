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

function Get-Certificate {
	param($subject)
	Get-AvailableCertificates | ?{ $_.Subject -eq $subject } | select -First 1
}

function Get-MakeCertPath {
	if( Get-Command makecert -ErrorAction SilentlyContinue ) {
		return "makecert"
	}
	if(Test-Path "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\") {
		$makeCertPath = ls "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\*\bin\makecert.exe" | select -ExpandProperty Fullname -last 1
	}
	if( $makeCertPath ) {
		return $makeCertPath
	}
	return "$PSScriptRoot\makecert.exe"
}

function Make-KeystoreCertificate {
	param($commonName="keystore@$($env:UserName)")
	[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | out-null
	$subject = "CN=$commonName"
	$cert = Get-Certificate $subject
	if( $cert -eq $null ) {
		$makecert = Get-MakeCertPath
		& "$makecert" -r -sk keystore -sky Exchange -n $subject -ss My | Out-Host
		Write-Host "Created certificate with subject $subject."
		$cert = Get-Certificate $subject
	}
	Write-Host "Using certificate with subject $($cert.Subject) thumbprint $($cert.Thumbprint)"
	$cert
}

function Delete-KeystoreData.ps1 {
	param( $keyName )
	$keyFile = Get-KeyFilePath $keyName
	if( Test-Path -PathType Leaf $keyFile ) {
		rm $keyFile
	}
}




