rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 EB FF E8 C8 FF FF FF FF 75 08 }
        $pattern1 = { 3D 00 01 00 00 F8 }
        $pattern2 = { 83 F8 01 74 E8 B4 DF }

    condition:
        any of them
}