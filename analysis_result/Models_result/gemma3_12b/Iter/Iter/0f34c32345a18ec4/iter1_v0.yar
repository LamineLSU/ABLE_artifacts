rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x41E174,action0=skip,bp1=0x41E189,action1=skip,bp2=0x41E19C,action2=skip,count=0"

    strings:
        $pattern0 = { 41 E1 74 5E 5D C3 5E 60 }
        $pattern1 = { 41 E1 89 EC 8B 45 08 8B 48 14 }
        $pattern2 = { 41 E1 9C 56 56 50 50 E8 74 }

    condition:
        any of them
}