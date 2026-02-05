rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 43 1C 00 00 ?? } // Specific call with offset and conditional jump
        $pattern1 = { E8 EE 82 FF FF ?? } // Another conditional call leading to decision
        $pattern2 = { E8 89 E0 FF FF ?? } // Third conditional call before exit

    condition:
        any of them
}