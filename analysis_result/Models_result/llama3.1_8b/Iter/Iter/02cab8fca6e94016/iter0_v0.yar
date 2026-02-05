rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 85 C0 6A 5B 5A 8B CE ?? ?? ?? }
        $pattern2 = { 6A 5B 5A 8B CE ?? ?? ?? 85 C0 }
        $pattern3 = { 8B FF 55 8B EC ?? ?? ?? }

    condition:
        any of them
}