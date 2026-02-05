rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checks for conditional exit decision"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF 74 12 }
        $pattern1 = { 83 F8 01 74 00 00 }
        $pattern2 = { FF 74 24 04 04 FF D0 }
}

condition:
    (test+je) | (cmp+mov) | (conditional jump)