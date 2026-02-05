rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 25 05 00 00 }
        $pattern1 = { E8 4B 16 89 00 ?? ?? ?? ?? 5D 00 3C }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 5D 00 3C }

    condition:
        any of them
}