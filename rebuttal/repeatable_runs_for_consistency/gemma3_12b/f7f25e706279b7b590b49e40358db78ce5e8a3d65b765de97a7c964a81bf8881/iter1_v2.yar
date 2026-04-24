rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x41E174,action0=skip,bp1=0x41E191,action1=skip,bp2=0x41E1B0,action2=skip,count=0"

    strings:
        $pattern0 = { 41 E1 74 8B 16 50 51 FF D2 }
        $pattern1 = { 41 E1 91 6A 35 6A 00 51 }
        $pattern2 = { 41 E1 B0 8B 16 50 51 52 }

    condition:
        any of them
}