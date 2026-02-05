rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using specific sequences from trace analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 0A 4C 7E 55 FF 15 BC A0 41 00 }
        $pattern1 = { C8 5C 8B EC C1 E8 75 10 }
        $pattern2 = { A8 01 74 2F 75 10 }

    condition:
        any of them
}