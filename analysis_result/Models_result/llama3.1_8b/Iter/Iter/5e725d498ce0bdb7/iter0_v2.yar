rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,count=0"

    strings:
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 FF D0 }
        $pattern2 = { 56 50 51 E8 ?? ?? ?? ?? 85 C0 FF D0 }

    condition:
        any of them
}