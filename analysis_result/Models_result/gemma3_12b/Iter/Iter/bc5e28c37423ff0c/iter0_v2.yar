rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 6A 00 51 8D B8 ?? ?? ?? ?? }
        $pattern1 = { 6A 00 51 8D B8 ?? ?? ?? ?? 52 }
        $pattern2 = { 52 8B 16 50 51 FF D2 5E }

    condition:
        any of them
}