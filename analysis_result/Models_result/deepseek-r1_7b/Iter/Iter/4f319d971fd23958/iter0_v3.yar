rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting memory reads and calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 ?? 8B 45 03 ?? 5A 8B CE E8 ?? ?? ?? ?? ?? ?? }
        $pattern1 = { ?? 85 C0 0F 84 8B 55 0C 8B 06 00 8B 55 0C }
        $pattern2 = { 5E F3 8A 5A 8B CE E8 ?? ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}