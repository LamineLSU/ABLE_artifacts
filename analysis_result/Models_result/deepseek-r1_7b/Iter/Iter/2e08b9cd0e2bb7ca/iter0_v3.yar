rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 5A 8B CE E8 ?? ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 74 ?? 1E 8D 86 ?? ?? 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 8B 45 ?? FC ?? ?? ?? ?? ?C 3A 5F }

    condition:
        any of them
}