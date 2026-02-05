rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D 0C 83 C4 14 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern2 = { 55 8B 45 08 8B 88 14 0A 00 56 6A 36 6A 00 51 8D B0 7C 0C 00 00 56 50 E8 44 09 00 00 }

    condition:
        any of them
}