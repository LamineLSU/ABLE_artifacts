rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 74 ?? }
        $pattern1 = { 8B CE 53 E8 ?? ?? ?? ?? }
        $pattern2 = { 33 FF FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}