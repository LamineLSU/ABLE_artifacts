rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 CC E8 6E FF FF C0 ?? }   // Combines push and call instructions with wildcards
        $pattern1 = { CC 5A E8 CE E8 ?? }        // Includes int3 call with wildcards for displacement
        $pattern2 = { 6A 5A 8B CE E8 ?? }        // Targets stack-based bypass attempt
}

condition:
    any_of($pattern0, $pattern1, $pattern2)
}