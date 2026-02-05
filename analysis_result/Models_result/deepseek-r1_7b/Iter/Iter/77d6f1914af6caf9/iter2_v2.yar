rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 E8 ?? 74 0C ?? 83 C4 ?? 85 C0 0F 84 ?? }
        $pattern1 = { FF EC 9E 6A ?? 5B 8A ?? FC 60 ?? 85 C0 FF EC 9E 6A ?? 5B 8A ?? FC 60 }
        $pattern2 = { 00 0F 38 7D 1B 5C 45 32 87 5D 0B 04 83 E9 FF 1E 70 ?? BF 2A 0B 6E 85 C0 }

    condition:
        any of them
}