rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { 8D 95 F0 FE FF FF 89 D9 8D 85 F0 FE FF FF 03 C3 }
        $pattern2 = { 83 F8 01 74 12 6A ?? 5A 8B CE }

    condition:
        any of them
}