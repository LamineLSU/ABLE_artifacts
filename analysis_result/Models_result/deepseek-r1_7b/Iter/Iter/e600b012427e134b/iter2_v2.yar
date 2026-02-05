rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 20 00 6A 48 5A ?? ?? ?? ?? }
        $pattern1 = { 74 C0 EA ?? ?? ?? ?? }
        $pattern2 = { 8B CE EC ?? 00 ?? }
    condition:
        any of them
}