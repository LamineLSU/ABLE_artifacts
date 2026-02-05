rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF C0 4E 8B 8C 3F 8D 3F ?? ?? ?? ?? ?? .C 0 }
        $pattern2 = { A3 F0 C1 41 FF C0 4E 8B EC 3F 8D 3F ?? ?? ?? ?? ?? .C 0 }

    condition:
        any of them
}