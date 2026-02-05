rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection in sandbox"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF 15 34 51 A1 03 ?? ?? ?? 74 1D ?? ?? ?? ?? 6F F8 }
        $pattern2 = { FF 15 C4 50 A1 03 ?? ?? ?? 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}