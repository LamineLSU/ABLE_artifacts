rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 8B 45 ?? }
        $pattern3 = { C3 8B 45 ?? 0F 84 ?? ?? ?? ?? EB ?? ?? ?? }

    condition:
        any of them
}