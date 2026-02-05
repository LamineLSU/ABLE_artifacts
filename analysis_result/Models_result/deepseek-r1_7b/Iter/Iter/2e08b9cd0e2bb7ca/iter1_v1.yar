rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using specific exit patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern1 = { E8 35 11 00 00 FF 35 FA 40 9E 0B A3 FE 40 9E 0B }
        $pattern2 = { E8 1F 11 00 00 FF 35 FE 40 9E 0B A3 FA 40 9E 0B }

    condition:
        any of them
}