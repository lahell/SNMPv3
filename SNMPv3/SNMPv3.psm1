$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )
$Public = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue )

foreach ($Import in @($Private + $Public))
{
	try
	{
		. $Import.FullName
	}
	catch
	{
		Write-Error -Message "Failed to import function $($Import.FullName): $_"
	}
}

Export-ModuleMember -Function $Public.BaseName
