rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 E3 FA FF FF 50 E8 ?? ?? ?? ?? }
        $pattern2 = { A1 88 85 C2 00 85 C0 74 07 50 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}