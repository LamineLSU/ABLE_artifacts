rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8F 96 B0 59 59 85 C0 ?? }
        $pattern1 = { 59 59 80 7B 28 02 ?? ?? }
        $pattern2 = { 0F 00 00 03 00 00 00 00 00 00 00 03 00 00 00 01 }
}

condition:
    any of them
}