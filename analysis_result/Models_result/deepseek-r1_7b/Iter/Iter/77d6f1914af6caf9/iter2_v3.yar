rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 FF 57 8B 45 FC }
        $pattern1 = { 89 45 FC F3 AA EB }
        $pattern2 = { FF 15 EC 36 38 00 E8 A9 01 00 00 E8 D8 F9 FF FF }
    condition:
        (any of them)
}