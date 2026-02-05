rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 96 B0 00 00 00 83 7D E8 14 0F 82 BE 20 00 00 }
        $pattern1 = { E8 76 49 00 00 59 59 85 C0 0F 85 F2 CF FF FF }
        $pattern2 = { 8B 7B 10 8B 7B 10 85 FF 74 1C 8B C7 E8 9C 1B 00 00 }

    condition:
        any of them
}