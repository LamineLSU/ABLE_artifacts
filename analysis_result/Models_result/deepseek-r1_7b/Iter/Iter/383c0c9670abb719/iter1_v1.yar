rule Bypass_Sample
{
    meta:
        description = "Evasion bypass targeting conditional jump after call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 45 ?? ?? 74 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? 3F 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { FF 15 2C ?? FF 15 A0 00 }

    condition:
        any of them
}