rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 45 03 ?? .? ? ?? .? ? 8B 45 FC }
        $pattern1 = { FF 75 08 FF 75 08 FF ?? ?? .? ? 8B C3 ?? .? ?. ? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? .? ?. ? 85 C0 }

    condition:
        any of them
}