rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 45 7E 05 0B 1F 8D 04 00 00 ?? 8B 45 0C ?? }
        $pattern1 = { FF C2 A0 36 79 57 00 00 00 85 C0 0F 84 ?? ?? ?? }
        $pattern2 = { 6A 8E 5D F8 EC CE 74 15 DC 10 00 FF 30 8C 7C 00 00 8B 45 8E 8C ?? }

    condition:
        any of them
}