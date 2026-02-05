rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting cache eviction"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? EA }
        $pattern1 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }. PUSH, POP, and TEST sequence
        $pattern2 = { FF 15 88 A0 3B ?? ?? ?? ?? 45 C7 }. Sequence leading to cache eviction with specific argument
    condition:
        any of them
}