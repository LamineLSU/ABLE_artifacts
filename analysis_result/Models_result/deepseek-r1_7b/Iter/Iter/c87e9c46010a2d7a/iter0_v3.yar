rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call/jump instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ??. }
        $pattern1 = { E8 ?? C7 F9 5F 4E }
        $pattern2 = { 74 ?? }

    condition:
        any of them
}