rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 84 C0 }
        $pattern1 = { 48 8B C8 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 8B CB FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}