rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Bypass Test EAX
        $pattern1 = { E8 25 05 00 00 85 C0 0F 84 ?? ?? ?? ?? } // Bypass Call and Test
        $pattern2 = { 50 53 68 ?? ?? ?? ?? 33 C9 } //Bypass Push and XOR

    condition:
        any of them
}