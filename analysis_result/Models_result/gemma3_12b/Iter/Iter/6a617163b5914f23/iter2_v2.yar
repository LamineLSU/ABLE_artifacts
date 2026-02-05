rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 48 75 44 00 FF 15 00 40 44 00 }
        $pattern1 = { 8B F0 6A 08 56 FF 15 04 40 44 00 }
        $pattern2 = { 81 FF 99 02 00 00 5F 5E }

    condition:
        any of them
}