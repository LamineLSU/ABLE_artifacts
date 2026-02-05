rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF 15 ?? ?? ?? ?? 56 53 6A FF 57 }
        $pattern2 = { E8 ?? ?? ?? ?? 8B DC 57 56 53 }

    condition:
        any of them
}