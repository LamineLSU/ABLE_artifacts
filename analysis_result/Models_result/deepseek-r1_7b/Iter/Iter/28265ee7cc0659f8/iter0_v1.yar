rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting exit processes"
        cape_options = "bp0=$BPPattern0+0,action0=skip,bp1=$BPPattern1+0,action1=skip,bp2=$BPPattern2+0,count=0"

    strings:
        $BPPattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?F }
        $BPPattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $BPPattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}