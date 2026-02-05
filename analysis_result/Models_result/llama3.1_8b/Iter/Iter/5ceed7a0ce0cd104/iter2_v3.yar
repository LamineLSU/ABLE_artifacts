rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+4,action0=skip,bp1=$pattern1+4,action1=skip,bp2=$pattern2+4,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 F7 25 00 00 83 F8 01 74 20 }
        $pattern1 = { FF 75 08 FF 15 3C F1 42 00 50 FF 15 40 F1 42 00 }
        $pattern2 = { E8 0B 00 00 00 59 FF 75 08 FF 15 A0 F1 42 00 }

    condition:
        any of them
}