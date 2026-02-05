rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 87 3D 00 00 83 F8 01 74 20 }
        $pattern1 = { FF 75 08 FF 15 10 61 3A 00 50 FF 15 14 61 3A 00 }
        $pattern2 = { FF 75 08 E8 0B 00 00 00 59 FF 75 08 FF 15 48 61 3A 00 }

    condition:
        any of them
}