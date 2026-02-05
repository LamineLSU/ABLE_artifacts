rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 83 F9 FF 00 74 ?? 8B 45 ?? E8 ?? ?? ?? ?? AE E9 ?? ?? ?? EB ?? 59 B9 ?? ?? ?? ?? E8 ?? }

    condition:
        any of them
}