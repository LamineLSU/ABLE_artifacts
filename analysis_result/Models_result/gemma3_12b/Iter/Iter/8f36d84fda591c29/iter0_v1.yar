rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 62 17 8B 45 08 8B 88 40 08 00 }
        $pattern1 = { 8B 45 08 8B 88 40 08 6A 36 5A }
        $pattern2 = { 6A 36 5A 8B CE E8 24 13 00 }

    condition:
        any of them
}