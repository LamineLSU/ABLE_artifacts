rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call/jump instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C7 26 ?? ?? 00 00 00 }
        $pattern1 = { E9 B5 FC ?? ?? ?? ?? ?? 00 00 }
        $pattern2 = { 74 08 04 04 ?? ?? 00 00 }

    condition:
        any of them
}