rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x0039108b+0,action0=skip,bp1=0x00391090+0,action1=skip,bp2=0x003910A0+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 87 3D 00 00 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 }
        $pattern2 = { FF 75 08 FF 15 10 61 3A 00 50 FF 15 14 61 3A 00 }

    condition:
        any of them
}