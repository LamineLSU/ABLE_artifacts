rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85C0 0F84 ?? ?? ?? ?? 8B45 ??
        $pattern1 = { E8?? 7407 ?? ?? ?? ?? ??85C0
        $pattern2 = { 6A5B 8BCE ?? ?? ?? ?? 85C0 }
    condition:
        any of them
}