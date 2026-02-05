rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting early conditional checks before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }  // Compares EAX to 0x3A and jumps
        $pattern1 = { FF 15 8C 42 5E 50 00 00 }  // Conditional jump before exit decision
        $pattern2 = { 8B 4F 4F 4F 4F 4F 4F 4F }  // Checks for specific instruction sequence at known address

    condition:
        any of them
}