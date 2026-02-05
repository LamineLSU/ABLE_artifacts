rule Bypass_Evasion
{
    meta:
        description = "Bypasses exit process by bypassing conditional jumps and memory accesses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B EC 0F 75 ?? ?? .? ?. ?? .? ?. E8 C8 FF FF FF }
        $pattern1 = { FF ?? 45 8B 3C ?? ?? ? ?? ?? ?? ?? 8B FC }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 ?? .? ?. ?? ? }
    condition:
        any of them
}