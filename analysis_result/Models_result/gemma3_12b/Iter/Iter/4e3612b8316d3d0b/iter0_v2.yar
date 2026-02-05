rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - First Call"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 }

    condition:
        any of them
}