rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - conditional skips targeting ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 0E 8C FF FE FF FF }  // Conditional skip after call
        $pattern1 = { FE FF FF FF FE FF FF ?? }  // Skip push instruction based on EAX
        $pattern2 = { C4 CC CC CC FE FF FF }  // Conditional bypass of exit check
}

    condition:
        any of them
}