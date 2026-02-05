rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific trace points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 00 C3 01 64 A1 00 00 00 ?? }
        $pattern1 = { 74 1A FF 75 08 50 8B 40 FC 83 C4 85 C0 }
        $pattern2 = { E8 F7 25 00 CE E8 6A ?? 5A 8B CE E8 }

    condition:
        any of them
}