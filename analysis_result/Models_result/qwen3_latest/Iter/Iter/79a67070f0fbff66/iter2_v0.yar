rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3B 4D FC 73 22 8B 55 C4 8B 45 E4 8B 0C 90 51 FF 15 F0 50 61 00 }
        $pattern1 = { 8B 0D 60 42 61 00 51 FF 15 18 50 61 00 6A 00 8B 4D F8 51 FF 15 F0 50 61 00 }
        $pattern2 = { FF 15 A4 50 61 00 }

    condition:
        any of them
}