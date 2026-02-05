rule EvasionBypass
{
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? 7A 5F }
        $pattern1 = { 6A 5A 8B CE ?? ?? ?? 39 5F }
        $pattern2 = { 39 0F 84 E9 ?? ?? ?? 7A 5F }

    condition:
        any of them
}