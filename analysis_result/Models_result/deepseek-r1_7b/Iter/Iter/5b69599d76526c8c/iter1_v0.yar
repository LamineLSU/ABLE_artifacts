rule Bypass_Sample
{
    meta:
        description = "Evasion exploiting function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {8B4508 E8 ?? ?? ?? ??}
        $pattern1 = {75 ?? 83C414 ?? E8 ?? ????
                     75 ?? 83C414 ?? E8 ?? ??}
        $pattern2 = {6A36 ?? 8B06 ?? E8 ?? ????

    condition:
        any of them
}