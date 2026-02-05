rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 B0 C8 F9 FF 6A ?? 5A 8B CE E8 ?? }
        $pattern1 = { E8 D1 C7 F9 FF 6A ?? 5A 8B CE E8 ?? }
        $pattern2 = { E8 6B 25 FE FF 0F 84 ?? ?? ? }

    condition:
        any of them
}