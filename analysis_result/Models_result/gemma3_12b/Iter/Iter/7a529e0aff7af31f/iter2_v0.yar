rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 8B FF 55 8B EC FF 75 08 FF 15 AC B0 41 00 59 FF 75 08 }
        $pattern2 = { 8B EE 5D 5E 33 CD 5B E8 57 26 00 00 8B E5 }

    condition:
        any of them
}