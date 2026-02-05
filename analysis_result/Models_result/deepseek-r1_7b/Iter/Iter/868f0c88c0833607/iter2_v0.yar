rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific memory accesses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? ?? ?? ?? FF 15 3C E1 DB 00 }
        $pattern1 = { E8 ?? ?? ?? ?? 8B 45 ?? ?? ?? ?? FF 15 40 E1 DB 00 }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 83 C4 ?? 74 20 FF 15 3CE1 DB 00 }

    condition:
        any of them
}