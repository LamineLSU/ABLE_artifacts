rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checked multiple locations"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC ?? ?? ?? ?? 56 ?? 8B 45 08 } // Early exit check
        $pattern1 = { 83 F8 01 74 12 ?? ?? ?? ?? 8B EC ?? } // Conditional before exit
        $pattern2 = { 83 F8 01 74 12 ?? 56 ?? ?? ?? 8D F8 } // Cache timing check
    condition:
        any of them
}