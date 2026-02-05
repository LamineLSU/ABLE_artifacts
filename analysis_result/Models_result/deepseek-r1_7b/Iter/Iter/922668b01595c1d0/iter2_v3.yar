rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit decision point with specific EAX test and conditional jump."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 75 74 12 C0 FF ?? } // Test EAX and conditional jump
        $pattern1 = { 64 A1 30 00 00 00 00 01 C1 E8 08 EA 08 A8 01 00 41 B9 30 }
        $pattern2 = ?? -- No need for a third pattern as we target multiple points
}

condition:
    (any of the patterns match in order)
}