rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 0C 8B 06 52 }
        $pattern1 = { 8B 16 50 51 6A 35 }
        $pattern2 = { 56 6A 36 6A 00 51 }

    condition:
        any of them
}