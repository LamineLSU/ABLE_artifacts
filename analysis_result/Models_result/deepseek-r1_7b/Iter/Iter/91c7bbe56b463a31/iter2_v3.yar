rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 74 6C 31 51 00 1E } // Specific test and mov instruction
        $pattern1 = { 8B 45 FC 20 00 0A 00 00 00 00 00 00 } // Conditional check before exit decision
        $pattern2 = { 68 E9 9F 7E 2C 1D 3B D4 5C DD 96 A9 } // Another conditional bypass point

    condition:
        any of them
}