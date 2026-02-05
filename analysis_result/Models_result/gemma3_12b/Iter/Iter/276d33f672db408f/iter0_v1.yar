rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 0C 8B 06 83 C4 14 52 5E 5D }
        $pattern1 = { 80 7B 49 4D E3 6E 5B 55 8B EC }
        $pattern2 = { 8D B0 7C 0C 56 6A 36 6A 00 6A 00 }

    condition:
        any of them
}