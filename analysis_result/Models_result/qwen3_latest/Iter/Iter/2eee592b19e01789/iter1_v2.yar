rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 84 C0 74 11 FF 15 ?? ?? ?? ?? }
        $pattern1 = { FF 15 ?? ?? ?? ?? 48 8B C8 8B D3 }
        $pattern2 = { 8B CB FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}