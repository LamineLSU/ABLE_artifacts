rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using trace data"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 40 34 D5 00 40 0F FF FF FF 75 08 08 }
        $pattern1 = { 40 34 D5 00 40 0F FF FF FF 75 08 08 40 0F FF FF FF 75 08 08 }
        $pattern2 = { 40 34 D5 00 40 0F FF FF FF 75 08 08 40 0F FF FF FF 75 08 08 40 0F FF FF }

    condition:
        (any of the patterns match)
}