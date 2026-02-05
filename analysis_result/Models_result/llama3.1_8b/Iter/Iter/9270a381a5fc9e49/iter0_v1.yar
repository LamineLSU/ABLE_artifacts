rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { F8 5D C3 FF D0 ?? ?? ?? }
        $pattern1 = { 9E 70 AC CE 13 BD ?? ?? ?? }
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}