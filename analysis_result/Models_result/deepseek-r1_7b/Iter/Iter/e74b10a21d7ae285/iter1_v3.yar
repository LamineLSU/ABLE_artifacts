rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule (6 patterns)"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 7E 00 3C 33 FF 5B 5E 5A 89 91 45 6C 6D 72 }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}