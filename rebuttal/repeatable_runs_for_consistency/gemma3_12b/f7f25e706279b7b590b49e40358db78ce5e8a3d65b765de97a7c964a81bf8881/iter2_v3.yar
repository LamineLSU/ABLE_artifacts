rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x41E174,action0=skip,bp1=0x41E19E,action1=skip,bp2=0x41E1AF,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 8B 16 50 50 51 FF D2 }
        $pattern1 = { E8 74 0A 00 00 8B 55 14 }
        $pattern2 = { 52 8B 16 50 50 51 }

    condition:
        any of them
}