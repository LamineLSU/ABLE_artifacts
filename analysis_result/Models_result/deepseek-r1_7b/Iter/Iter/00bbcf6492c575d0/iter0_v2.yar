rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF ?? 5A ?? 8B EC E8 FF FF ?? }
        $pattern1 = { 6A 5B 5A ?? ?? 8B 45 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { E8 C8 FF FF FF ?? ?? ?? ?? 8B 45 ?? ?? ?? ?? 85 C0 }
    condition:
        any of them
}