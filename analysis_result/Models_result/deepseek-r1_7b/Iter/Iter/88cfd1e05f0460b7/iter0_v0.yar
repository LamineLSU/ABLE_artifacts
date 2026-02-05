rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $pattern1 = { 75 0C ?? 8B 45 ?? ?? E8 ?? ?? ?? ?? }
        $pattern2 = { ?? ?? ?? ?? 85 C0 ?? F8 8A ?? }

    condition:
        any of them
}