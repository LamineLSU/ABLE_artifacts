rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 88 13 00 00 FF D3 8B 35 ?? ?? ?? ?? }
        $pattern1 = { FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 83 C4 04 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}