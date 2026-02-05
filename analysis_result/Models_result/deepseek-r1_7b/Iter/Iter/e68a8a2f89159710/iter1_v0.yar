rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 25 ?? ??? } (6 bytes)
        $pattern1 = { 74 0F 85 ?? ??? } (6 bytes)
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ??? } (9 bytes)

    condition:
        any of them
}