rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 00 40 40 00 E8 90 F6 FF FF 8B D8 83 C4 04 85 DB 74 1B 90 8B 45 08 }
        $pattern1 = { 74 07 50 FF 15 50 B0 AB 00 FF 74 24 10 FF 15 D8 90 AB 00 FF 74 24 14 FF 15 B8 90 AB 00 EB 19 }
        $pattern2 = { 83 7C 24 18 00 74 0C FF 74 24 18 6A 00 FF 15 34 91 AB 00 57 FF 15 38 91 AB 00 85 F6 74 07 }

    condition:
        any of them
}