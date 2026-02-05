rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 8D 95 F0 FE FF FF 89 D9 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { 33 DB BA 21 05 00 53 53 68 11 14 01 44 C7 85 ?? }
        $pattern3 = { 8B FF 55 8B EC FF 75 08 E8 ?? ?? ?? ?? 59 FF 75 08 }

    condition:
        any of them
}