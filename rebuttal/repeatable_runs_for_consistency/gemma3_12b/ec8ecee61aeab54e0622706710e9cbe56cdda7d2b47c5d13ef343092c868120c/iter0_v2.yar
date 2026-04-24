rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4C 24 7C E8 19 01 00 00 50 }
        $pattern1 = { 68 AC 30 3F 03 57 }
        $pattern2 = { 68 08 3D 3F 03 8D 4C 24 14 }

    condition:
        any of them
}