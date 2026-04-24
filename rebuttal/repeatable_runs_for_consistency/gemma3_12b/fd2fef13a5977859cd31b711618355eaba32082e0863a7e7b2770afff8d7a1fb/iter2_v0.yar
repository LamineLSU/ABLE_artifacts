rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=0x41B90B+0,action0=skip,bp1=0x41B91C+0,action1=skip,bp2=0x41B920+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 F7 25 00 00 }
        $pattern1 = { 83 F8 01 74 20 64 A1 30 00 00 00 }
        $pattern2 = { FF 75 08 FF 15 3C F1 42 00 50 FF 15 40 F1 42 00 }

    condition:
        any of them
}