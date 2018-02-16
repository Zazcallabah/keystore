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
