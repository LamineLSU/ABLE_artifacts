rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 B0 62 45 00 E9 5A FF FF FF 6A 01 83 EC 18 }
        $pattern1 = { 8D 45 F8 50 FF 15 AC 63 45 00 FF 75 08 51 }
        $pattern2 = { 68 48 3E 46 00 8D 4D E8 50 E8 01 C1 FF FF }

    condition:
        any of them
}