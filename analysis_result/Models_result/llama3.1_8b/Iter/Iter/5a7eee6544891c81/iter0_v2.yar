rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=0,action1=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? C1 FF FF 55 8B EC FF 75 08 }

    condition:
        any of them
}