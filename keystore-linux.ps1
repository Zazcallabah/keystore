# This file is sourced from github.com/Zazcallabah/keystore

$script:_certkeys = @{}

function script:_certkey
{
	param($privateKey)
	if($script:_certkeys -eq $null)
	{
		$script:_certkeys = @{}
	}
	if(!$script:_certkeys.ContainsKey($privateKey))
	{
		$passkey = read-host -AsSecureString "Enter pass phrase for '$privateKey'"
		$script:_certkeys.Add($privateKey, $passkey)
	}
	return  $script:_certkeys[$privateKey] | ConvertFrom-SecureString -asplaintext
}

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

function Set-Certkey
{
	param($privateKey, $passPhrase)
	if($script:_certkeys -eq $null)
	{
		$script:_certkeys = @{}
	}
	if($script:_certkeys.containskey($privateKey))
	{
		$script:_certkeys.remove($privateKey)
	}
	$script:_certkeys.Add($privateKey, (ConvertTo-SecureString -AsPlainText -String $passPhrase))
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

	try
	{
		$passkey = _certkey $privateKey
		$result = $passkey | openssl pkeyutl -decrypt -passin stdin -inkey $privateKey -in $tmpfile 2>&1
		$errorresult = $result | ?{ $_ -is [System.Management.Automation.ErrorRecord] } | %{ "$_" }
		if($errorresult -ne $null)
		{
			throw $errorresult
		}
	}
	catch
	{
		$script:_certkeys.Remove($privateKey)
		write-error $_
		throw $_
	}
	finally
	{
		remove-item $tmpfile
	}
	return $result | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }

}

function Encrypt
{
	param( [string]$data, $privateKey )
	$tmpfilein = "$PSScriptRoot/$([System.IO.Path]::GetRandomFileName())"
	$tmpfileout = "$PSScriptRoot/$([System.IO.Path]::GetRandomFileName())"
	$passkey = _certkey $privateKey
	$data | set-content -encoding utf8 $tmpfilein
	$passkey | openssl pkeyutl -encrypt -passin stdin -inkey $privateKey -out $tmpfileout -in $tmpfilein
	if(!(test-path $tmpfileout))
	{
		remove-item $tmpfileout
		remove-item $tmpfilein
		throw "Did not get data from openssl"
	}
	$keyDataBytes = [System.IO.File]::ReadAllBytes($tmpfileout)
	remove-item $tmpfileout
	remove-item $tmpfilein
	return $keyDataBytes | ToBase64
}

function Make-KeystoreCert
{
	param($filename, $folder, $passphrase)
	if($filename -eq $null -or $filename -eq "")
	{
		$filename = "keystore.pem"
	}
	if($folder -eq $null)
	{
		$folder = "~/.ssh"
	}
	$name = "$($folder.trimend('/'))/$filename"
	if($passphrase -eq $null)
	{
		ssh-keygen -m PKCS8 -t rsa -b 4096 -f $name | out-host
	}
	else
	{
		ssh-keygen -m PKCS8 -t rsa -b 4096 -f $name -N $passphrase | out-host
	}
	return $name
}

function Get-KeystoreData
{
	param(
		[parameter(mandatory=$true)]
		[string] $keyName,
		$cert
	)
	[System.Reflection.Assembly]::LoadWithPartialName("System.Security") | out-null

	$keyFile = Get-KeyFilePath $keyName
	if( Test-Path -PathType Leaf $keyFile )
	{
		$keyData = get-content -Encoding Utf8 -Path $keyFile
		if($cert -eq $null){
			$cert = Get-Cert -hash $keyData[0]
		}
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

	$inputcert = $cert

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
	$retrievedData = Get-KeystoreData -keyName $keyName -cert $inputcert

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
	param( $keyName, $cert )
	$data = Get-KeystoreData -keyName $keyName -cert $cert
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


