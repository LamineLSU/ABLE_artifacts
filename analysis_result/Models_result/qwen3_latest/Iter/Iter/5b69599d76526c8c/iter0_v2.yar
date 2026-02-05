rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting code patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 ?? 52 FFD0 }
        $pattern1 = { 50 51 FFD2 5E 5D C3 }
        $pattern2 = { 8D B0 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? }

    condition:
        any of them
}