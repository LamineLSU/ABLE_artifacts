rule Bypass_Sample
{
    meta:
        description = "Evasion bypass targeting specific memory addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 45 ?? ?? ?? ?? ED ?? }
        $pattern1 = { 6A 5F 9C 7D ?? ?? ?? ?? 8B FC ?? ?? }
        $pattern2 = { DD FF 3E 01 ?? ?? ?? ?? 8B FC ?? }

    condition:
        any of them
}