rule Bypass_Sample_Evaded
{
    meta:
        description = "Evasion bypass detection targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? 1A 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { FF ?? ?? ?? ?? ?? ?? F0 FC ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 0F 84 ?? 0F 85 ?? ?? ?? }

    condition:
        any of them
}