rule Bypass_Sample
{
    meta:
        description = "Evasion bypass for exit point"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 75 0C ?? ?? F8 E8 ?? ?? ?? ?? 8B FC }
        $pattern2 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}