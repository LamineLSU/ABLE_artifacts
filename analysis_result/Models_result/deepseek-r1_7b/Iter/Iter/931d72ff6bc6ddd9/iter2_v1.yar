rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific evasive code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }  // Initial test and jump
        $pattern1 = { 8D 95 F0 FE FF FF A1 88 85 21 00 E8 B3 03 00 00 }  // Conditional call before exit
        $pattern2 = { 8B C7 EB 03 EA ED }  // Specific instruction sequence

    condition:
        any of them
}