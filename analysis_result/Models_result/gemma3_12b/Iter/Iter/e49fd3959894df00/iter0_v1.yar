rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 75 07 FF 15 44 74 44 00 }
        $pattern1 = { 50 E8 82 3D 01 00 83 C4 18 56 FF 15 44 74 44 00 }
        $pattern2 = { 81 FB 09 03 00 00 7D 07 FF 15 34 50 43 00 }

    condition:
        any of them
}