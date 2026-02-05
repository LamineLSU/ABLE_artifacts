rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific instruction patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? FF 74 24 04 }
        $pattern1 = { FF 74 24 04 ?? ?? ?? FF 15 5C E0 40 00 }
        $pattern2 = { E8 F7 25 00 00 83 F8 01 74 20 64 A1 30 00 00 00 FF 15 5C 01 B8 00 }

    condition:
        any of them
}