rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern+0,action0=skip,count=0"

    strings:
        $pattern = { E8 C8 FF FF FF FF 59 FF 75 08 }

    condition:
        any of them
}