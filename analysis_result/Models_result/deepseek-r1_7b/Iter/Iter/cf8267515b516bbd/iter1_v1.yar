rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checking for API exit conditions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 F3 ?? ?? ?? ?? }
        $pattern1 = { 8B 4D 6C ?? ?? ?? ?? ?? ?? ?? ?? }
        $pattern2 = { 8B 4D 0C ?? 00 00 00 00 ?? ?? 51 ?? E8 ?? F3 ?? }
}

condition:
    (any of them)