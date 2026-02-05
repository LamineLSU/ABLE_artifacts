rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 88 4C 04 90 40 3D 97 00 00 00 }
        $pattern1 = { FF 15 C8 81 85 00 89 E0 8D 4C 24 18 }
        $pattern2 = { FF 15 AC 81 85 00 E8 EF 0F 00 00 }

    condition:
        any of them
}