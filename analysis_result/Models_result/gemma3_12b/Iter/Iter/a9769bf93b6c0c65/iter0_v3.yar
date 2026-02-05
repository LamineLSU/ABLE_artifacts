rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Skip test eax, eax and je
        $pattern1 = { E8 E3 FA FF FF 50 53 6A 40 53 68 40 11 B9 00 33 C9 } //Skip 00B91680h call
        $pattern2 = { FF 15 3C E1 3F 00 50 FF 15 40 E1 3F 00 } // Skip FF153CE13F00 call

    condition:
        any of them
}