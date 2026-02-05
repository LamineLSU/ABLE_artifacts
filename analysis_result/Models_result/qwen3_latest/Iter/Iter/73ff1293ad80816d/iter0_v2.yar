rule Evasion_Bypass
{
    meta:
        description = "Detects potential evasion techniques by identifying suspicious control flow and memory manipulation patterns."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF ?? ?? ?? ?? 83 C4 ?? 85 C0 }
        $pattern2 = { 83 C4 ?? 85 C0 74 ?? }

    condition:
        any of ($pattern0, $pattern1, $pattern2)
}