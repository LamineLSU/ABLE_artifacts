rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE ?? ?? ?? ?? FF D7 }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 08 FF D7 }
        $pattern2 = { 85 C0 ?? ?? FF D7 }

    condition:
        any of them
}