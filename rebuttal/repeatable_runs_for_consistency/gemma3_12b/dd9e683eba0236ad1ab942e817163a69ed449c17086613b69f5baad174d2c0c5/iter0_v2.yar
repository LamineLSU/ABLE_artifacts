rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 06 83 C4 14 52 52 FF D0 }
        $pattern1 = { 56 6A 35 6A 35 6A 00 51 E8 44 09 00 00 }
        $pattern2 = { 8B 45 10 8B 4D 0C 83 C4 14 52 8B 16 }

    condition:
        any of them
}