rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 8B 4D F8 FF 24 8D 96 3B 24 00 68 18 68 26 00 }
        $pattern2 = { 85 C0 0F 85 F5 00 00 00 8B 45 ?? }

    condition:
        any of them
}