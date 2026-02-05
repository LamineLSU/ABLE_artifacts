rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern1 = { E8 87 3D 00 00 8B 45 FC }
        $pattern2 = { FF 15 48 61 3A 00 FF 15 14 61 3A 00 }

    condition:
        any of them
}