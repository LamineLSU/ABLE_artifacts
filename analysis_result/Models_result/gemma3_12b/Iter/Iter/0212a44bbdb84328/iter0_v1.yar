rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Bypass CALL at 0040E7F6"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B FF 55 8B EC ?? ?? ?? ?? 83 F8 01 }

    condition:
        any of them
}