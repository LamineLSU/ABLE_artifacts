rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using specific call patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 00 00 00 00 }
        $pattern1 = { E8 74 FF AF F0 00 }
        $pattern2 = { E8 0D 00 00 C0 00 }

    condition:
        (match $pattern0) || (match $pattern1) || (match $pattern2)
}