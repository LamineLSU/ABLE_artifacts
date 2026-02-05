rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 C0 8B D3 F9 FF FF B9 C8 00 00 00 F3 AF 75 EF F7 B5 30 F9 FF FF }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}