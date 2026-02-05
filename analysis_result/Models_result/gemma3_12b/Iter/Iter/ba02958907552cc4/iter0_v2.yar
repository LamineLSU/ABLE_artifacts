rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 00 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 74 FA FF FF 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { E8 B3 03 00 00 A1 88 85 EF 00 85 C0 74 07 50 FF 15 88 A0 EF 00 }

    condition:
        any of them
}