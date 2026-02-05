rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C0 10 00 0F 85 ?? ?? ?? ?? }
        $pattern1 = { FF 15 D8 54 41 00 FF 75 08 6A 00 }
        $pattern2 = { 83 7D 10 00 75 32 }

    condition:
        any of them
}