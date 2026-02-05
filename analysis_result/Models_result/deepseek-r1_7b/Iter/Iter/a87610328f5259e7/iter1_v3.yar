rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - improved with specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 D2 61 7A 85 C0 00 D2 61 7C 74 12 00 D2 61 7E 6A 5B 00 D2 61 80 5A 00 D2 61 81 8B 4F 00 D2 61 83 E8 25 05 00 00 }
        $pattern1 = { 00 D2 61 F8 FF 15 2C A1 D2 00 }
        $pattern2 = { 00 D2 61 E7 A1 88 85 D2 00 00 D2 61 EC 85 C0 00 D2 61 EE 74 07 00 D2 61 F0 50 }
    condition:
        any of them
}