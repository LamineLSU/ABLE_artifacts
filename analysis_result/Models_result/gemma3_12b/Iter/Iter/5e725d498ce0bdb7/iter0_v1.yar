rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { 6A 35 6A 00 51 8D B0 98 0C 00 00 }
        $pattern2 = { 7C C0 JL 00 41 E2 90 H 1E 79 B4 }

    condition:
        any of them
}