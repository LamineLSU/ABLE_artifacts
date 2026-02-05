rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? EA ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? EA ?? }
        $pattern2 = { 7D 5E FC 8B 3E 8B 0C ?? ?? ?? ?? EA ?? }

    condition:
        any of them
}