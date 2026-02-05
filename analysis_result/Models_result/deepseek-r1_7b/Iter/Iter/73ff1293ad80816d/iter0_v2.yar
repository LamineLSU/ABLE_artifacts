rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? 1A 8B FC ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 59 FF 75 ?? ?? 8B 45 ?? }
        $pattern2 = { F8 C3 6A 8B CE E8 ?? ?? ?? 85 C0 ?? }
    condition:
        any of them
}