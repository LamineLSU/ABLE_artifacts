rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC } // Specific test on EAX
        $pattern1 = { C1 E8 08 A8 01 } // Conditional check before exit
        $pattern2 = { FF 75 08 F1 42 00 } // Conditional call bypass

    condition:
        (any of them)
}