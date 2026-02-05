rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC }  // Sequence from call TEST EAX
        $pattern1 = { FF 75 08 ,F F1 5A CB 04 10 0 }  // Conditional check before exit
        $pattern2 = { RD TS C, 0F 4C }  // Timing-based check

    condition:
        any of them
}