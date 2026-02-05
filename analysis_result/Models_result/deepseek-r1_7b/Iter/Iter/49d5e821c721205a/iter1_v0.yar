rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5B 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { F4 7E 74 13 74 0D 74 05 8B EC 8A 5F ?? ?? ?? ?? ??
        $pattern2 = { 53 2C 53 6E 53 91 ?? ?? ?? ?? FF C8 ??
    condition:
        any of them
}