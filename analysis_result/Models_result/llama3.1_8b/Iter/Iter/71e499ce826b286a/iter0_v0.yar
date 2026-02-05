rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 E3 FA FF FF FF }
        $pattern1 = { 53 6A 40 5A 8B CE E8 B3 03 00 00 FF 15 ?? ?? ?? }
        $pattern2 = { 53 6A 40 5A 8B CE E8 B4 17 00 00 FF 15 ?? ?? ?? }

    condition:
        any of them
}