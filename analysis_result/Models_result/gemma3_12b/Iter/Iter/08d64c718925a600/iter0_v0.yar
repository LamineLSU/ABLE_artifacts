rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 83 7D 10 00 75 32 68 00 C2 41 00 }
        $pattern2 = { FF 15 3C 51 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}