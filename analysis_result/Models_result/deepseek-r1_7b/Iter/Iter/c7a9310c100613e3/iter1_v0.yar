rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5C 8B FF 03 7E C9 }  // Conditional jump before exit
        $pattern1 = { 6A F8 4D FC 8B FF }  // Address manipulation check
        $pattern2 = { E8 2A 7E 00 00 5C }  // Exit decision bypass

    condition:
        any of them
}