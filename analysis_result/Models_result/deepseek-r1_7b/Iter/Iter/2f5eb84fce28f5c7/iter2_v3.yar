rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting call/jump instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 74 ?? ?? .? ?. ?? .? ? }
        $pattern2 = { 6A ?? 5A 8B CE ?? .? ?. ?? .? ?. 83 C4 }

    condition:
        any of them
}