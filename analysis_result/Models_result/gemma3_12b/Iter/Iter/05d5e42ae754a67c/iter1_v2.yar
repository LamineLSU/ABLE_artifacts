rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0,action0=skip,bp1=0,action1=skip,bp2=0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 6A 35 6A 00 51 8D B0 98 0C 00 00 }
        $pattern1 = { 56 50 E8 74 0A 00 00 }
        $pattern2 = { 52 8B 16 50 51 FF D2 }

    condition:
        any of them
}