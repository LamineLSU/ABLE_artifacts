rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 64 A1 30 00 00 00 }
        $pattern1 = { 83 EC 18 53 56 57 E8 0E F6 FF FF }
        $pattern2 = { FF 15 10 20 40 00 8D 70 01 8D 04 36 }

    condition:
        any of them
}