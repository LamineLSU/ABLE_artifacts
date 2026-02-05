rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x41E164+0,action0=skip,bp1=0x41E179+0,action1=skip,bp2=0x41E18E+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 35 6A 00 51 50 }
        $pattern1 = { 8B 45 08 8B 48 14 56 50 }
        $pattern2 = { E8 74 0A 00 00 8B 55 14 }

    condition:
        any of them
}