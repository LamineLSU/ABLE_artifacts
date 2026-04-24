rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B 5A } // test eax, je, push, pop
        $pattern1 = { 74 ?? E8 ?? ?? ?? ?? } // je, call (offsets wildcards)
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? } // push ebx, call (exit point)

    condition:
        any of them
}