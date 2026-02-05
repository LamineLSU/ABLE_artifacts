rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting conditional jumps before exit decisions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern1 = { 6A 5B 74 0F 84 00 5A }
        $pattern2 = { 50 8C 01 31 5E 9B 00 }

    condition:
        any of them
}