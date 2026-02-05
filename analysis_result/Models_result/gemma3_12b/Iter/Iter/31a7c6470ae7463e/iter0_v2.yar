rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B 45 0C 8B 06 83 C4 14 52 52 FF D2 }
        $pattern1 = { 55 8B 45 08 8B 88 14 0A 00 00 56 6A 36 6A 00 51 8D B0 7C 0C 00 00 }
        $pattern2 = { 8B 45 08 8B 88 14 0A 00 00 56 6A 36 6A 00 51 8D }

    condition:
        any of them
}