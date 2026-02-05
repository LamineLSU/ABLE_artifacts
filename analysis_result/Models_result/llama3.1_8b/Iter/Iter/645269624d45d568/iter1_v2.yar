rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 CD 3D 00 00 83 F8 01 74 20 64 A1 30 00 00 00 }
        $pattern1 = { 8B 40 68 C1 E8 08 A8 01 75 10 FF 75 08 E8 0B 00 00 00 }
        $pattern2 = { 59 FF 75 08 90 E8 94 DB 19 75 CC }

    condition:
        any of them
}