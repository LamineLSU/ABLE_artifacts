rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF FF }
        $pattern1 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 33 DB BA 21 05 00 53 53 53 68 }

    condition:
        any of them
}