rule Bypass_Evasion_Paths
{
    meta:
        description = "Evasion bypass detection for specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5B 8B CE E8 ?? .? ?. ?? .? 83 C4 ?? .? ?. ?? }
        $pattern1 = { 75 ?? .? ?. ?? ? 0F 84 E8 ?? .? ?. ?? .? 8D 8F }
        $pattern2 = { 50 ?? 50 8B 5E E8 CE ?? .? ?. ?? .? }

    condition:
        any of them
}