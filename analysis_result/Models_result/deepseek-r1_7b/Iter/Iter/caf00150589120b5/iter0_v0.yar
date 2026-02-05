rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule for ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF75 08 E8 C8 FFFF }  // Includes context before call
        $pattern1 = { 6A ?? 5A 8B CE E8 ???? ?? }  // Combines multiple instructions
        $pattern2 = { BA 70 F4 00 8B EC FF75 08 }  // Different instruction sequence

    condition:
        any of them
}