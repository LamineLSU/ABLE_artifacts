rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific exit decision checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 55 8B EC C1 E8 A8 01 }  // Specific test and jump sequence
        $pattern1 = { E8 D2 2F F9 03 75 10 55 FF 75 08 E8 D2 2F F9 03 }  // Conditional check before exit call
        $pattern2 = { 00 00 00 30 64 A1 30 00 00 00 8B 40 68 01 C1 E8 75 10 A8 01 }  // Specific address and sequence

    condition:
        any of them
}