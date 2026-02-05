rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B E5 83 F9 01 74 ?? }
        $pattern1 = { 64 A1 30 00 00 00 E8 CD 3D 00 00 }
        $pattern2 = { C1 EB 08 A8 01 75 10 FF 75 08 }

    condition:
        any of them
}