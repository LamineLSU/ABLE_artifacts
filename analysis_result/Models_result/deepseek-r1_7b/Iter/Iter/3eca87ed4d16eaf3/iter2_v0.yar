rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting common jump targets"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 00 ?? 04 ?? } // Jump to main process address with variable offset
        $pattern1 = { 74 ?? ?? } // Conditional jump near target in main process
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? } // Call with variable stack manipulation

    condition:
        any of them
}