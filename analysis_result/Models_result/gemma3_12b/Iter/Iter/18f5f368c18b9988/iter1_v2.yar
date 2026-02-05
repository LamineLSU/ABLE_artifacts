rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 11 74 05 8B C0 FC 85 C9 }
        $pattern1 = { 68 30 1B 0F 00 6A 00 57 E8 A5 29 02 00 }
        $pattern2 = { 8B B5 08 FC FF FF 89 85 CC FB FF FF A1 E8 E0 48 00 }

    condition:
        any of them
}