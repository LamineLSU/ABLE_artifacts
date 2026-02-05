rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85C0 7412 6A5B 8BCE E8 ?? ?? ?? ?? ??. }
        $pattern1 = { E8 ?? ?? ?? ?? ?? ?? }
        $pattern2 = { ?? ?? ?? ?? FF 15 AC B0 41 00 }

    condition:
        any of them
}