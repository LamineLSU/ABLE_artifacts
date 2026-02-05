rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x40E7F6+0,action0=skip,bp1=0x40E7FC+0,action1=skip,bp2=0x40E7F3+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 C8 FF FF FF 59 }
        $pattern1 = { FF 75 08 FF 15 AC B0 41 00 83 F8 01 74 12 }
        $pattern2 = { FF 75 08 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}