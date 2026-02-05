rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checked conditional calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 42 7B 11 FF 15 5C C2 4C 00 }
        $pattern1 = { 00 42 7B 11 E8 C1 FF FF FF }
        $pattern2 = { 00 42 7B 1A FF 15 5C C2 4C 00 }

    condition:
        (any)
}