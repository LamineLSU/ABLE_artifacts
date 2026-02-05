rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 35 FC C1 41 00 }
        $pattern1 = { 8B 45 FC 75 08 FF 35 FC C1 41 00 }
        $pattern2 = { EB 38 FF 35 FC C1 41 00 }
    condition:
        any of them
}