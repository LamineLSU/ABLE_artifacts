rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 00 10 00 00 0F 82 }
        $pattern1 = { 48 83 F8 FF 74 4E }
        $pattern2 = { FF 15 B2 0E 00 00 }

    condition:
        any of them
}