rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 0A ?? 0B ?? 0C 0D 7E 96 0E }
        $pattern1 = { E8 83 FC 0E 84 0F 82 01 8B 5E ?? 83 C4 FF 0A ?? }
        $pattern2 = { 6A 5A 8B CE E8 07 8B 4D 00 85 C0 0F 84 0E 0F }

    condition:
        any of them
}