rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x41E1B4,action0=skip,bp1=0x41E1DC,action1=skip,bp2=0x41E1F0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 51 51 50 6A 35 }
        $pattern1 = { 56 56 50 50 E8 74 }
        $pattern2 = { 52 52 8B 16 50 50 }

    condition:
        any of them
}