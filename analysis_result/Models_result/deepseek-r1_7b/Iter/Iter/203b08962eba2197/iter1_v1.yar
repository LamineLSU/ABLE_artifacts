rule Bypass_Sample
{
    meta:
        description = "Evasion bypass by calling an address dependent on test condition"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 F4 89 FE ?? ?? E8 0F C0 }
        $pattern1 = { D1 D9 EA X TE ST EA X JZ ?? 8A FF ?? 8B ?? C0 6A ?? 5A }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? F4 ?? FE JZ 0F C0 }

    condition:
        any of them
}