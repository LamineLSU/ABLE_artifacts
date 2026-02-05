rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern3 = { 8B 45 ?? 56 E8 ?? ?? ?? ?? }

    condition:
        any of them
}