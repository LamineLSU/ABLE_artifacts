rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting evocation checks and conditional calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 45 7E 6A 9C 83 FF }
        $pattern1 = { E8 F7 25 00 00 00 FF 75 08 FF 15 3C F1 42 00 }
        $pattern2 = { 64 A1 30 00 00 00 00 8B 40 68 C1 E8 08 A8 01 }

    condition:
        any of them
}