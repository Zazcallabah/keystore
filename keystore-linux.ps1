# This file is sourced from github.com/Zazcallabah/keystore

filter GetBytes
{
	[System.Text.Encoding]::UTF8.GetBytes( $_ )
}

filter GetString
{
	param([Parameter(ValueFromPipeline)][byte]$b)
	begin
	{
		$array = @()
	}
	process
	{
		$array += $b
	}
	end
	{
		return [System.Text.Encoding]::UTF8.GetString( $array )
	}
}

filter ToBase64
{
	param([Parameter(ValueFromPipeline)][byte]$b)
	begin
	{
		$array = @()
	}
	process
	{
		$array += $b
	}
	end
	{
		return [System.Convert]::ToBase64String( $array )
	}
}

filter FromBase64
{
	[System.Convert]::FromBase64String( $_ )
}

filter ToHex
{
	param([Parameter(ValueFromPipeline)][byte]$b)
	begin
	{
		$str = new-object System.Text.StringBuilder
	}
	process
	{
		$r = $str.Append($b.ToString( "X2" ))
	}
	end
	{
		$str.ToString()
	}
}

filter SHA1
{
	$sha1 = (new-object System.Security.Cryptography.SHA1Managed).ComputeHash( ($_ | GetBytes) )
	return $sha1 | ToHex
}

function Get-LocalKeyStore
{
	$localStore = join-path "~" ".keystore"
	if( !(test-path $localStore ) )
	{
		mkdir $localStore | out-null
	}
	$localStore
}

function Get-KeyFilePath
{
	param($keyName)
	Join-Path (Get-LocalKeyStore) ($keyName | SHA1)
}

function Get-Cert
{
	param(
		$name,
		$hash
	)
	if( $name -ne $null -and $name -ne "")
	{
		$file = "~/.ssh/$name"
		if( (test-path -pathtype Leaf $file) )
		{
			# todo verify correctnes of file format?
			# todo what about public vs private?
			return $file
		}
		else
		{
			throw "invalid key name $name"
		}
	}
	if( $hash -ne $null )
	{
		# its almost always going to be the default cert anyway, so try with that first
		if((test-path "~/.ssh/keystore.pem"))
		{
			$thumb = get-content -encoding utf8 -raw "~/.ssh/keystore.pem" | SHA1
			if($thumb -eq $hash)
			{
				return "~/.ssh/keystore.pem"
			}
		}
		$allcerts = get-childitem "~/.ssh" -File
		foreach($certfile in $allcerts)
		{
			$thumb = get-content -encoding utf8 -raw $certfile.fullname | SHA1
			if($thumb -eq $hash)
			{
				return $certfile.FullName
			}
		}
		throw "no key with hash $hash found"
	}
	throw "invalid input parameters to get-cert"
}

function Get-DefaultCertificate
{
	return Get-Cert -name "keystore.pem"
}


function Delete-KeystoreData
{
	param( $keyName )
	$keyFile = Get-KeyFilePath $keyName
	if( Test-Path -PathType Leaf $keyFile )
	{
		remove-item $keyFile
	}
}

function Delete-KeystoreCredential
{
	param( $keyName )
	Delete-KeystoreData $keyname
}

function Decrypt
{
	param( $keyDataBase64, $privateKey )

	$tmpfile = "$PSScriptRoot/$([System.IO.Path]::GetRandomFileName())"
	$keyDataBytes = $keyDataBase64 | FromBase64
	$ignore = [System.IO.File]::WriteAllBytes( $tmpfile, $keyDataBytes )

	$result = openssl pkeyutl -decrypt -inkey $privateKey -in $tmpfile
	remove-item $tmpfile
	return $result
}

function Encrypt
{
	param( [string]$data, $privateKey )
	$tmpfile = "$PSScriptRoot/$([System.IO.Path]::GetRandomFileName())"
	$data | openssl pkeyutl -encrypt -inkey $privateKey -out $tmpfile
	$keyDataBytes = [System.IO.File]::ReadAllBytes($tmpfile)
	remove-item $tmpfile
	return $keyDataBytes | ToBase64
}

function Make-KeystoreCert
{
	param($filename)
	if($filename -eq $null -or $filename -eq "")
	{
		$filename = "keystore.pem"
	}
	$name = "~/.ssh/$filename"
	ssh-keygen -m PKCS8 -t rsa -b 4096 -f $name | out-host
	return $name
}

function Get-KeystoreData
{
	param(
		[parameter(mandatory=$true)]
		[string] $keyName
	)
	[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | out-null

	$keyFile = Get-KeyFilePath $keyName
	if( Test-Path -PathType Leaf $keyFile )
	{
		$keyData = gc -Encoding Utf8 -Path $keyFile
		$cert = Get-Cert -hash $keyData[0]
		if(!$cert)
		{
			throw ("Cannot find the requested certificate: {0}" -f $keyData[0])
		}
		$keyDataString= $keyData[2]
		$data = Decrypt $keyDataString $cert
		if( $keyData[1] -eq "json" )
		{
			return $data | ConvertFrom-Json
		}
		return $data
	}
}

function Set-KeystoreData
{
	param(
		[parameter(mandatory=$true)]
		[string] $keyName,
		[parameter(mandatory=$true)]
		$data,
		$cert
	)

	if( $cert -eq $null )
	{
		$cert = Get-DefaultCertificate
	}

	if( !(Test-path $cert ))
	{
		throw "Couldn't find proper certificate"
		return
	}

	if( $data -eq $null -or $data -eq "" )
	{
		throw "Must specify data to encrypt"
		return
	}

	if( $data.GetType().Name -eq "String" )
	{
		$stringdata = $data
		$type = "string"
	}
	else
	{
		$stringdata = $data | ConvertTo-Json -Depth 99
		$type = "json"
	}


	$keyfile = Get-KeyFilePath $keyName
	$thumb = get-content -encoding utf8 -raw $cert | SHA1
	$encrypted = Encrypt $stringData $cert
	$keydata = @( $thumb, $type, $encrypted )
	Set-Content -Encoding Utf8 -Path $keyfile -Value $keydata
	$retrievedData = Get-KeystoreData -keyName $keyName

	if( $retrievedData -eq $null )
	{
		throw "Failed to encrypt data with keyname $keyname"
	}

	if( ($retrievedData | ConvertTo-Json -Depth 99) -ne ($data | ConvertTo-Json -Depth 99) )
	{
		throw "Failed to encrypt data with keyname $keyname"
	}
	return $retrievedData
}

function Get-KeystoreCredential
{
	param( $keyName )
	$data = Get-KeystoreData -keyName $keyName
	if($data -and $data.u -and $data.p)
	{
		return new-object System.Management.Automation.PSCredential( $data.u, (ConvertTo-SecureString -AsPlainText -Force -String $data.p) )
	}
}

function Set-KeystoreCredential
{
	param(
		[parameter(mandatory=$true, position=0)]
		[string] $keyName,
		[parameter(mandatory=$true, position=1, parametersetname="UsernamePassword")]
		[string] $username,
		[parameter(mandatory=$true, position=2, parametersetname="UsernamePassword")]
		[string] $password,
		[parameter(mandatory=$true, position=1, parametersetname="PSCredential")]
		[System.Management.Automation.PSCredential] $credential,
		$cert
	)

	if( $credential -ne $null )
	{
		$networkcredential = $credential.getNetworkCredential()
		$username = $networkcredential.Username
		$password = $networkcredential.Password
	}

	if( !($username -and $password) )
	{
		throw "Must specify credential or non-empty username+password"
		return
	}

	$data = Set-KeystoreData -keyName $keyName -data @{"u"=$username; "p"=$password } -cert $cert

	if( $data -eq $null )
	{
		throw "Failed to encrypt credential with keyname $keyname"
	}

	if($data.u -and $data.p)
	{
		return new-object System.Management.Automation.PSCredential( $data.u, (ConvertTo-SecureString -AsPlainText -Force -String $data.p) )
	}
	else
	{
		throw "Failed to encrypt credential with keyname $keyname"
	}
}


