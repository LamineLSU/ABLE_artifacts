rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using specific call-test-je patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF ?? ?? ?? ?? E8 F7 25 00 00 ?? }
        $pattern1 = { 83 F8 01 74 20 ?? ?? ?? ?? C1 E8 08 ?? }
        $pattern2 = { A8 01 75 10 FF 75 08 ?? }

    condition:
        (any of the patterns)
}