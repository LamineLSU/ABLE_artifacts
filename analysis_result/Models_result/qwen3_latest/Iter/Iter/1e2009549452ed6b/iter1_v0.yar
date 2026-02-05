rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 FF 74 ?? 8B 45 ?? }
        $pattern1 = { 6A 03 FF 15 ?? ?? ?? ?? }
        $pattern2 = { FF 15 ?? ?? ?? ?? EB ?? }

    condition:
        any of them
}