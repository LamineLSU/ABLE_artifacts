rule Bypass_Evasion_Patterns
{
    meta:
        description = "Evasion bypass patterns targeting specific code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 C8 FF FF ?? ?? ?? ?? ?? 8B 45 FF ?? }
        $pattern1 = { FF 75 08 74 ?? ?? ?? ?? 83 C4 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 ?? ?? ?? ?? }

    condition:
        any of them
}