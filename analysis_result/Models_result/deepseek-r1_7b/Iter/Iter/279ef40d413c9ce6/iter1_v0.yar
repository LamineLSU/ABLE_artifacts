rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call dword ptr instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF 15 28 ?? ?? ?? ?? A3 F0 ?? ??.00 41 C1 41 00 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { FF 15 3C 51 41 00 8B 45 ?? ?? ?? ?? 75 0C ??.02 85 C0 }

    condition:
        any of them
}