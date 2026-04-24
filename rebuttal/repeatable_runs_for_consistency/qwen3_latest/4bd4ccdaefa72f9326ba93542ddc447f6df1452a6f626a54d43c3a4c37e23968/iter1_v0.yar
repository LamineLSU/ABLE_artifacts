rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 8B CF FF 15 ?? ?? ?? ?? }
        $pattern1 = { 48 83 F8 FF 74 ?? }
        $pattern2 = { 89 74 24 ?? BA 00 00 00 C0 }

    condition:
        any of them
}