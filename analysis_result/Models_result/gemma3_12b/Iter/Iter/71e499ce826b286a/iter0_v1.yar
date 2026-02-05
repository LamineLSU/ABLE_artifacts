rule Bypass_CALL
{
    meta:
        description = "Bypass CALL instruction"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 48 8B 45 ?? 45 ?? 48 8B 41 ?? 48 8B 55 ?? 48 8B 65 ?? 48 8B 75 ?? 48 8B 85 ?? ?? ?? ?? }

    condition:
        any of them
}