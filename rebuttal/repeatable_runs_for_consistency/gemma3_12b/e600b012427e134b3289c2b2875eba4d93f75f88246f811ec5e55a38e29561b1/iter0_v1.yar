rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 8B 40 68 }
        $pattern1 = { 56 68 14 E7 71 00 }
        $pattern2 = { 64 A1 30 00 00 00 8B 40 68 }

    condition:
        any of them
}