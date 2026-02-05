rule Bypass_Evasion
{
    meta:
        description = "Bypasses evasion through multiple paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE ?? ?? }
        $pattern1 = { 74 ?? ??. ?? ?? }
        $pattern2 = { 85 C0 ?? ??. 74 ?? ??? }
}